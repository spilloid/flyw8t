(() => {
  "use strict";

  const frameBytes = 4096;
  const pendingLimit = 16;
  const outputLimit = 320 * 1024;
  const retryWindow = 5 * 60 * 1000;
  const endLabels = {
    closed: "Session ended",
    process_exited: "PowerShell exited",
    policy_disabled: "Local terminal policy was disabled",
    access_revoked: "Terminal access was revoked",
    expired: "The reconnect window expired",
    agent_stopped: "The agent stopped the session",
    unavailable: "The agent could not open or resume PowerShell",
    busy: "Another attachment is using this terminal",
    invalid_input: "The agent refused terminal input",
  };

  function mount() {
    const panel = document.querySelector("[data-terminal-ws]");
    if (!panel) return;

    const screen = panel.querySelector("#background-terminal-screen");
    const status = panel.querySelector("#background-terminal-status");
    const detail = panel.querySelector("#background-terminal-detail");
    const warning = panel.querySelector("#background-terminal-warning");
    const interrupt = panel.querySelector("#background-terminal-interrupt");
    const end = panel.querySelector("#background-terminal-end");
    const target = new URL(panel.dataset.terminalWs, location.href);
    if (target.origin !== location.origin || typeof Terminal !== "function") {
      status.textContent = "Terminal unavailable";
      return;
    }
    const sessionPath = target.pathname.replace(/\/ws$/u, "");
    target.protocol = target.protocol === "https:" ? "wss:" : "ws:";

    const terminal = new Terminal({
      allowProposedApi: false,
      cols: 120,
      rows: 30,
      disableStdin: true,
      scrollback: 1000,
      fontFamily: "ui-monospace, Cascadia Mono, Consolas, monospace",
      fontSize: 12,
      theme: { background: "#10151d", foreground: "#e7edf6", cursor: "#d6e1f4" },
      linkHandler: { activate() {} },
    });
    // The remote program may color and position text. It cannot open URLs or write the clipboard.
    for (const code of [8, 52]) terminal.parser.registerOscHandler(code, () => true);
    terminal.open(screen);

    let socket;
    let attachment = null;
    let attached = false;
    let sequence = 1;
    let receivedOffset = 0;
    let displayedOffset = 0;
    let queuedBytes = 0;
    let retryAt = 0;
    let retryDelay = 500;
    let retryTimer;
    let ending = false;
    let checkingTermination = false;
    let finished = false;
    let nativeInput = null;
    let imeInput = null;
    let lostInput = false;
    let lostOutput = false;
    let transientWarning = "";
    const pending = new Set();

    function show(label, tone, message = "") {
      status.textContent = label;
      status.className = `badge ${tone}`;
      detail.textContent = message;
    }

    function showWarning() {
      const messages = [];
      if (lostInput) messages.push("Delivery of some input is unconfirmed.");
      if (lostOutput) messages.push("Some earlier output is no longer available.");
      if (transientWarning) messages.push(transientWarning);
      const message = messages.join(" ");
      if (warning.textContent !== message) warning.textContent = message;
      warning.hidden = !message;
    }

    function updateControls() {
      const writable = Boolean(attachment && !ending && !finished);
      terminal.options.disableStdin = !writable;
      interrupt.disabled = !writable;
      end.disabled = !attached || ending || finished;
      panel.dataset.terminalState = writable ? "attached" : "read_only";
    }

    function finish(label, tone, message = "") {
      finished = true;
      attachment = null;
      if (pending.size) lostInput = true;
      pending.clear();
      window.clearTimeout(retryTimer);
      show(label, tone, message);
      showWarning();
      updateControls();
      socket?.close();
    }

    function sendInput(data) {
      if (!attachment || ending || finished || !data || socket?.readyState !== WebSocket.OPEN) return;
      if (new TextEncoder().encode(data).length > frameBytes) {
        transientWarning = "This input exceeds 4 KiB. Paste smaller sections.";
        showWarning();
        return;
      }
      if (pending.size >= pendingLimit || socket.bufferedAmount >= 128 * 1024) {
        transientWarning = "Terminal input is backed up. Wait for delivery before trying again.";
        showWarning();
        return;
      }
      const number = sequence++;
      socket.send(JSON.stringify({ type: "input", sequence: number, data }));
      pending.add(number);
      transientWarning = "";
      showWarning();
    }

    // xterm also emits protocol replies to some output sequences. Forward data only during
    // a native input event, or printable IME text deferred until that event has propagated.
    for (const name of ["keydown", "keypress", "beforeinput", "input", "paste", "compositionend"]) {
      screen.addEventListener(name, (event) => {
        if (!event.isTrusted) return;
        nativeInput = event;
        window.setTimeout(() => { if (nativeInput === event) nativeInput = null; }, 0);
        if (name === "compositionend" || (name === "keydown" && event.keyCode === 229)) {
          imeInput = event;
          // Let xterm's target listener run its zero-delay composition timer first.
          window.setTimeout(() => window.setTimeout(() => {
            if (imeInput === event) imeInput = null;
          }, 0), 0);
        }
      }, true);
    }
    terminal.attachCustomKeyEventHandler((event) => event.isTrusted);
    terminal.onData((data) => {
      if (nativeInput?.eventPhase || (imeInput && !/[\x00-\x1f\x7f-\x9f]/u.test(data))) sendInput(data);
    });

    interrupt.addEventListener("click", (event) => {
      if (!event.isTrusted) return;
      sendInput("\u0003");
      terminal.focus();
    });
    async function checkTermination(deadline) {
      if (finished) return;
      try {
        const reply = await fetch(`${sessionPath}/status`, { cache: "no-store" });
        if (reply.ok) {
          const report = await reply.json();
          if (report.state === "ended") {
            const label = Object.hasOwn(endLabels, report.reason) ? endLabels[report.reason] : "Session ended";
            finish(label, "neutral");
            return;
          }
          if (report.state === "termination_unconfirmed" || report.state === "rejected") {
            finish("Termination unconfirmed", "unknown", "The agent has not confirmed termination.");
            return;
          }
        }
      } catch {
        // The session might end before this browser can read the receipt.
      }
      if (Date.now() >= deadline) {
        finish("Termination unconfirmed", "unknown", "The agent has not confirmed termination.");
        return;
      }
      retryTimer = window.setTimeout(() => checkTermination(deadline), 2000);
    }

    async function endWhileDetached() {
      checkingTermination = true;
      window.clearTimeout(retryTimer);
      socket?.close();
      try {
        const reply = await fetch(`${sessionPath}/end`, {
          method: "POST",
          body: new URLSearchParams({ csrf: panel.dataset.terminalCsrf }),
        });
        if (reply.status === 202) {
          show("Termination pending", "unknown", "Waiting for the agent to confirm termination.");
          await checkTermination(Date.now() + retryWindow + 15000);
          return;
        }
      } catch {
        // A failed request provides no receipt that the server accepted the close.
      }
      checkingTermination = false;
      ending = false;
      transientWarning = "The server did not confirm receipt of the end request.";
      showWarning();
      updateControls();
      scheduleRetry();
    }

    end.addEventListener("click", (event) => {
      if (!event.isTrusted || !attached || ending || finished) return;
      ending = true;
      updateControls();
      show("Ending session", "busy", "Waiting for the agent to confirm termination.");
      if (attachment && socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "close" }));
      } else {
        void endWhileDetached();
      }
    });

    function validOffset(value) {
      return Number.isSafeInteger(value) && value >= 0;
    }

    function receive(frame) {
      let message;
      try {
        message = JSON.parse(frame.data);
      } catch {
        return false;
      }
      if (!message || typeof message.type !== "string") return false;
      if (message.type === "ready") {
        if (attachment || typeof message.attachment !== "string" || !message.attachment ||
            message.account !== panel.dataset.terminalAccount || !validOffset(message.offset) ||
            message.offset < displayedOffset) return false;
        if (message.offset > displayedOffset) {
          terminal.reset();
          displayedOffset = message.offset;
          lostOutput = true;
        }
        receivedOffset = displayedOffset;
        attachment = message.attachment;
        attached = true;
        sequence = 1;
        retryAt = 0;
        retryDelay = 500;
        show("Connected", "good");
        showWarning();
        updateControls();
        terminal.focus();
        return true;
      }
      if (message.type === "termination_pending" && ending) {
        show("Termination pending", "unknown", "Waiting for the agent to confirm termination.");
        return true;
      }
      if (attachment && message.attachment !== attachment) return false;
      if (message.type === "ended" || message.type === "rejected") {
        const normal = message.type === "ended" && ["closed", "process_exited"].includes(message.reason);
        const label = Object.hasOwn(endLabels, message.reason) ? endLabels[message.reason] : "Session unavailable";
        finish(label, normal ? "neutral" : "bad");
        return true;
      }
      if (!attachment) return false;
      if (message.type === "ack" && Number.isSafeInteger(message.sequence)) {
        pending.delete(message.sequence);
        return true;
      }
      if (message.type !== "output" || message.offset !== receivedOffset || !Array.isArray(message.data) ||
          !message.data.length || message.data.length > frameBytes || queuedBytes + message.data.length > outputLimit ||
          !message.data.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) return false;

      const bytes = Uint8Array.from(message.data);
      const endOffset = receivedOffset + bytes.length;
      if (!validOffset(endOffset)) return false;
      receivedOffset = endOffset;
      queuedBytes += bytes.length;
      terminal.write(bytes, () => {
        displayedOffset = endOffset;
        queuedBytes -= bytes.length;
      });
      return true;
    }

    function scheduleRetry() {
      if (finished) return;
      if (Date.now() >= retryAt) {
        finish("Reconnection stopped", "unknown", "The agent has not confirmed the session outcome.");
        return;
      }
      const deadline = new Date(retryAt).toLocaleTimeString();
      show("Reconnecting", "unknown", `Trying to resume until ${deadline}.`);
      retryTimer = window.setTimeout(() => {
        // Wait for xterm to finish writing old frames before asking for replay.
        if (queuedBytes || Date.now() >= retryAt) scheduleRetry();
        else connect();
      }, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 5000);
    }

    function connect() {
      const connection = new WebSocket(target.href);
      socket = connection;
      attachment = null;
      let opened = false;
      const timeout = window.setTimeout(() => {
        if (!attachment) connection.close();
      }, 8000);
      connection.addEventListener("open", () => {
        opened = true;
        connection.send(JSON.stringify({ type: "attach", csrf: panel.dataset.terminalCsrf, offset: displayedOffset }));
      });
      connection.addEventListener("message", (frame) => {
        if (socket !== connection || finished) return;
        if (!receive(frame)) connection.close(1002, "Unexpected terminal frame");
        if (attachment || finished) window.clearTimeout(timeout);
      });
      connection.addEventListener("close", () => {
        window.clearTimeout(timeout);
        if (socket !== connection || finished) return;
        if (ending) {
          if (checkingTermination) return;
          finish("Termination unconfirmed", "unknown", "The connection closed before the agent confirmed termination.");
          return;
        }
        attachment = null;
        if (pending.size) lostInput = true;
        pending.clear();
        transientWarning = "";
        showWarning();
        updateControls();
        if (!attached && !opened && !retryAt) {
          finish("Could not connect", "bad");
          return;
        }
        if (!retryAt) retryAt = Date.now() + retryWindow;
        scheduleRetry();
      });
    }

    updateControls();
    connect();
  }

  mount();
})();
