import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("../src/terminal.js", import.meta.url), "utf8");

class Events {
  events = new Map();

  addEventListener(name, listener) {
    this.events.set(name, listener);
  }

  emit(name, detail = {}) {
    this.events.get(name)?.(detail);
  }
}

function browser(fetch) {
  const nodes = new Map();
  const panel = {
    dataset: { terminalWs: "/devices/test/background-terminal/sessions/session/ws",
      terminalCsrf: "browser-csrf", terminalAccount: "local_system" },
    querySelector(selector) {
      if (!nodes.has(selector)) nodes.set(selector, new Events());
      return nodes.get(selector);
    },
  };
  const node = (id) => panel.querySelector(`#background-terminal-${id}`);
  const sockets = [];
  const timers = new Map();
  let nextTimer = 1;
  let term;

  class ProtocolSocket extends Events {
    static OPEN = 1;
    readyState = 0;
    bufferedAmount = 0;
    sent = [];

    constructor(url) {
      super();
      this.url = url;
      sockets.push(this);
    }

    open() {
      this.readyState = 1;
      this.emit("open");
    }

    send(data) {
      this.sent.push(JSON.parse(data));
    }

    close(code = 1000) {
      if (this.readyState === 3) return;
      this.readyState = 3;
      this.emit("close", { code });
    }

    receive(data) {
      this.emit("message", { data: JSON.stringify(data) });
    }
  }

  class Console {
    parser = { registerOscHandler: (code, handler) => this.blocked.set(code, handler) };
    blocked = new Map();
    callbacks = [];
    resets = 0;

    constructor(options) {
      this.options = options;
      term = this;
    }

    write(bytes, callback) {
      this.callbacks.push({ bytes: [...bytes], callback });
    }

    reset() { this.resets += 1; }
    onData(handler) { this.send = handler; }
    attachCustomKeyEventHandler(handler) { this.trusts = handler; }
    open() {}
    focus() {}
  }

  runInNewContext(script, {
    URL, URLSearchParams, TextEncoder, fetch,
    location: { href: "https://lab.example/device", origin: "https://lab.example" },
    document: { querySelector: () => panel },
    window: {
      setTimeout(fn, delay) {
        const id = nextTimer++;
        timers.set(id, { fn, delay });
        return id;
      },
      clearTimeout(id) { timers.delete(id); },
    },
    WebSocket: ProtocolSocket,
    Terminal: Console,
  });

  function type(data, isTrusted = true) {
    const event = { isTrusted, eventPhase: 1 };
    node("screen").emit("keydown", event);
    event.eventPhase = 2;
    term.send(data);
    event.eventPhase = 0;
  }

  function ready(socket, attachment = "first", offset = 0, account = "local_system") {
    socket.open();
    socket.receive({ type: "ready", account, attachment, offset });
  }

  function runTimer(atLeast, atMost) {
    const pair = [...timers].find(([, timer]) => timer.delay >= atLeast && timer.delay <= atMost);
    assert.ok(pair, "expected a retry timer");
    timers.delete(pair[0]);
    pair[1].fn();
  }

  return { sockets, term, node, type, ready, runTimer };
}

test("opens only for the verified account, sends typed input and confirms close", () => {
  const b = browser();
  const first = b.sockets[0];
  assert.equal(first.url, "wss://lab.example/devices/test/background-terminal/sessions/session/ws");
  b.ready(first);
  assert.deepEqual(first.sent, [{ type: "attach", csrf: "browser-csrf", offset: 0 }]);
  assert.equal(b.node("status").textContent, "Connected");
  assert.equal(b.node("end").disabled, false);

  b.type("x\r");
  b.node("interrupt").emit("click", { isTrusted: true });
  assert.deepEqual(first.sent.slice(1), [
    { type: "input", sequence: 1, data: "x\r" },
    { type: "input", sequence: 2, data: "\u0003" },
  ]);
  first.receive({ type: "ack", attachment: "first", sequence: 1 });
  first.receive({ type: "ack", attachment: "first", sequence: 2 });
  b.node("end").emit("click", { isTrusted: true });
  assert.deepEqual(first.sent[3], { type: "close" });
  first.receive({ type: "termination_pending" });
  assert.equal(b.node("status").textContent, "Termination pending");
  assert.equal(b.term.options.disableStdin, true);
  first.receive({ type: "ended", attachment: "first", reason: "closed" });
  assert.equal(b.node("status").textContent, "Session ended");
  assert.equal(b.node("warning").hidden, true);

  const wrong = browser();
  wrong.ready(wrong.sockets[0], "first", 0, "network_service");
  assert.equal(wrong.term.options.disableStdin, true);
  assert.equal(wrong.sockets[0].readyState, 3);
});

test("keeps automatic terminal replies and untrusted DOM input local", () => {
  const b = browser();
  const socket = b.sockets[0];
  b.ready(socket);
  assert.equal(b.term.options.allowProposedApi, false);
  assert.equal(b.term.blocked.get(8)("https://other.example"), true);
  assert.equal(b.term.blocked.get(52)("clipboard-content"), true);
  b.term.send("\x1b[0n");
  b.type("injected", false);
  b.node("interrupt").emit("click", { isTrusted: false });
  b.node("end").emit("click", { isTrusted: false });
  b.type("a".repeat(4097));
  assert.equal(socket.sent.length, 1);
  assert.match(b.node("warning").textContent, /exceeds 4 KiB/);
  b.type("permitted");
  assert.deepEqual(socket.sent[1], { type: "input", sequence: 1, data: "permitted" });
});

test("resumes from the last rendered byte without replaying input", () => {
  const b = browser();
  const first = b.sockets[0];
  b.ready(first);
  b.type("pending");
  first.receive({ type: "output", attachment: "first", offset: 0, data: [32, 27, 91] });
  assert.deepEqual(b.term.callbacks[0].bytes, [32, 27, 91]);
  first.close(1006);
  assert.match(b.node("warning").textContent, /input is unconfirmed/);
  assert.equal(b.node("status").textContent, "Reconnecting");
  b.runTimer(500, 500);
  assert.equal(b.sockets.length, 1);
  b.term.callbacks[0].callback();
  b.runTimer(1000, 1000);

  const second = b.sockets[1];
  b.ready(second, "second", 5);
  assert.deepEqual(second.sent, [{ type: "attach", csrf: "browser-csrf", offset: 3 }]);
  assert.equal(b.term.resets, 1);
  assert.match(b.node("warning").textContent, /earlier output is no longer available/);
  b.type("fresh");
  assert.deepEqual(second.sent[1], { type: "input", sequence: 1, data: "fresh" });
});

test("never reports a completed termination after the socket closes without an end event", () => {
  const b = browser();
  const socket = b.sockets[0];
  b.ready(socket);
  b.node("end").emit("click", { isTrusted: true });
  socket.close(1006);
  assert.equal(b.node("status").textContent, "Termination unconfirmed");
  assert.equal(b.node("end").disabled, true);
});

test("end while detached uses browser CSRF and waits for the agent's receipt", async () => {
  const requests = [];
  let confirm;
  const b = browser(async (url, options) => {
    requests.push([url, options]);
    if (url.endsWith("/end")) return { status: 202 };
    return new Promise((resolve) => { confirm = resolve; });
  });
  const socket = b.sockets[0];
  b.ready(socket);
  socket.close(1006);
  assert.equal(b.node("end").disabled, false);
  b.node("end").emit("click", { isTrusted: true });
  await new Promise(setImmediate);
  assert.match(requests[0][0], /\/sessions\/session\/end$/);
  assert.equal(requests[0][1].method, "POST");
  assert.equal(requests[0][1].body.get("csrf"), "browser-csrf");
  assert.match(requests[1][0], /\/sessions\/session\/status$/);
  assert.equal(b.node("status").textContent, "Termination pending");
  confirm({ ok: true, json: async () => ({ state: "ended", reason: "closed" }) });
  await new Promise(setImmediate);
  assert.equal(b.node("status").textContent, "Session ended");
});
