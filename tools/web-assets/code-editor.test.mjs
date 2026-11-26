import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { EditorState } from "@codemirror/state";
import { editorPhrases } from "./code-editor-phrases.js";

test("the policy editor passes all its Razor-localized phrases to CodeMirror", async () => {
  const view = await readFile(new URL("../../src/Nergal.Web/Views/Management/Policies.cshtml", import.meta.url), "utf8");
  const editor = view.match(/<textarea id="raw-bundle-json"[\s\S]*?<\/textarea>/)?.[0];
  assert.ok(editor, "Expected the policy JSON textarea");

  const attributes = [...editor.matchAll(/data-(editor-[a-z-]+)="@L\["([^"]+)"\]"/g)];
  const localized = (key) => `[translated] ${key}`;
  const dataset = Object.fromEntries(attributes.map(([, attribute, key]) => [
    attribute.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()),
    localized(key),
  ]));
  const phrases = editorPhrases(dataset);
  const state = EditorState.create({ extensions: EditorState.phrases.of(phrases) });

  for (const [attribute, key] of attributes.map(([, name, key]) => [name, key])) {
    if (attribute === "editor-label") continue; // The editor content label uses a separate ARIA attribute.
    assert.equal(state.phrase(key), localized(key), attribute);
  }
  assert.equal(Object.keys(phrases).length, attributes.length, "Each phrase has a Razor attribute, with Replace shared");
  assert.equal(state.phrase("replace"), localized("Replace"));
});

test("missing labels use English and CodeMirror keeps replacement announcement positions", () => {
  const state = EditorState.create({
    doc: '{"key": 1, "key": 2}',
    extensions: EditorState.phrases.of(editorPhrases({
      editorFind: "",
      editorReplace: "Replace",
      editorReplacedMatchOnLine: "se reemplazó la coincidencia en la línea $",
      editorReplacedMatches: "coincidencias reemplazadas: $",
    })),
  });

  assert.equal(state.phrase("Indent lines"), "Indent lines");
  assert.equal(state.phrase("Find"), "Find");
  assert.equal(state.phrase("Replace"), "Replace");
  assert.equal(state.phrase("replace"), "replace");
  assert.equal(state.phrase("replaced match on line $", 7), "se reemplazó la coincidencia en la línea 7");
  assert.equal(state.phrase("replaced $ matches", 2), "coincidencias reemplazadas: 2");
  assert.equal(state.doc.toString(), '{"key": 1, "key": 2}');
});
