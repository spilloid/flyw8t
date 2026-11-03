// Script editor (ADR-0014): Tab inserts a tab, and a file chosen to upload is read into the text box, to review before
// saving. Nothing else. Without this script the page still works: paste instead of uploading.
"use strict";
(() => {
  const src = document.getElementById("source");
  if (!src) return;
  // Esc, then Tab, leaves the box as usual, so the keyboard is never trapped.
  let leave = false;
  src.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { leave = true; return; }
    if (e.key !== "Tab" || e.shiftKey || e.ctrlKey || e.altKey || e.metaKey || leave) { leave = false; return; }
    e.preventDefault();
    // insertText keeps the browser's undo history; setRangeText is the fallback.
    if (!document.execCommand("insertText", false, "\t")) {
      src.setRangeText("\t", src.selectionStart, src.selectionEnd, "end");
    }
  });
  src.addEventListener("blur", () => { leave = false; });

  const pick = document.getElementById("upload");
  const status = document.getElementById("upload-status");
  if (!pick || !status) return;
  pick.closest("[hidden]")?.removeAttribute("hidden");
  const max = Number(pick.dataset.max);
  pick.addEventListener("change", async () => {
    const f = pick.files && pick.files[0];
    if (!f) return;
    if (f.size > max) { status.textContent = `${f.name} is larger than ${max / 1024} KiB; not loaded.`; return; }
    const text = await f.text();
    if (text.includes("\u0000")) { status.textContent = `${f.name} is not a text file; not loaded.`; return; }
    src.value = text;
    status.textContent = `Loaded ${f.name}. Review it, then save.`;
    pick.value = "";
    src.focus();
  });
})();
