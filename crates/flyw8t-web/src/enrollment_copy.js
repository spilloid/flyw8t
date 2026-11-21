(() => {
  if (!window.isSecureContext || typeof navigator.clipboard?.writeText !== "function") return;

  function enableCopy(buttonId, fieldId, statusId, success) {
    const button = document.getElementById(buttonId);
    const field = document.getElementById(fieldId);
    const status = document.getElementById(statusId);
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(field.value);
        status.textContent = success;
      } catch {
        field.focus();
        field.select();
        status.textContent = "Clipboard access was denied. Use your device’s Copy command on the selected text.";
      }
    });
    button.hidden = false;
  }

  enableCopy("copy-commands", "enrollment-commands", "commands-status", "Setup commands copied.");
  enableCopy("copy-token", "enrollment-token", "token-status", "Enrollment token copied.");
})();
