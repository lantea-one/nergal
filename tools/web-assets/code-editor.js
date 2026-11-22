import { basicSetup, EditorView } from "codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter } from "@codemirror/lint";
import { HighlightStyle, syntaxHighlighting, indentRange } from "@codemirror/language";
import { tags } from "@lezer/highlight";

// Enhance only explicitly marked code fields. Server validation remains authoritative.
const colors = HighlightStyle.define([
  { tag: tags.propertyName, color: "var(--editor-property)" },
  { tag: tags.string, color: "var(--editor-string)" },
  { tag: [tags.number, tags.bool, tags.null], color: "var(--editor-literal)" },
]);
const appearance = EditorView.theme({
  "&": { backgroundColor: "var(--surface)", color: "var(--text)", border: "1px solid var(--border-strong)", borderRadius: "6px" },
  "&.cm-focused": { outline: "2px solid var(--primary)", outlineOffset: "2px" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", fontSize: "0.85rem", overflow: "auto" },
  ".cm-content": { minHeight: "280px", caretColor: "var(--text)", padding: "10px 0" },
  ".cm-gutters": { backgroundColor: "var(--surface-subtle)", color: "var(--text-muted)", borderColor: "var(--border)" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "var(--surface-subtle)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "var(--editor-selection)" },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--text)" },
  ".cm-tooltip, .cm-panels": { backgroundColor: "var(--surface)", color: "var(--text)", borderColor: "var(--border-strong)" },
  ".cm-search input": { maxWidth: "100%", color: "var(--text)", background: "var(--surface)" },
});

for (const field of document.querySelectorAll("textarea[data-code-editor='json']")) {
  const host = document.createElement("div");
  host.className = "code-editor-host";
  field.after(host);
  const view = new EditorView({
    parent: host,
    doc: field.value,
    extensions: [basicSetup, json(), linter(jsonParseLinter()), appearance, syntaxHighlighting(colors),
      EditorView.contentAttributes.of({ "aria-label": field.dataset.editorLabel || "JSON code editor", "aria-describedby": field.getAttribute("aria-describedby") || "", spellcheck: "false" }),
      EditorView.updateListener.of(update => {
        if (update.docChanged) field.value = update.state.doc.toString();
      }),
    ],
  });
  field.hidden = true;
  // Labels continue to focus the enhanced input, and Tab retains normal keyboard navigation.
  document.querySelector(`label[for="${field.id}"]`)?.addEventListener("click", () => view.focus());
  field.form?.addEventListener("submit", () => { field.value = view.state.doc.toString(); });
  field.form?.addEventListener("reset", () => setTimeout(() => {
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: field.value } });
  }, 0));
  const toolbar = document.createElement("div");
  toolbar.className = "code-editor-toolbar";
  const format = document.createElement("button");
  format.type = "button";
  format.className = "btn btn-secondary btn-sm";
  format.textContent = "Indent lines";
  const status = document.createElement("span");
  status.className = "muted";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  format.addEventListener("click", () => {
    // Parser-aware indentation preserves all values, duplicate keys, and invalid input for server diagnostics.
    view.dispatch({ changes: indentRange(view.state, 0, view.state.doc.length) });
    status.textContent = "Indentation updated. Preview checks policy compatibility.";
  });
  toolbar.append(format, status);
  host.before(toolbar);
}
