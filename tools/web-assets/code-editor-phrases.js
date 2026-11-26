// CodeMirror phrase keys are case-sensitive. Preserve its lowercase English
// replace button when the shared resource uses its English fallback.
export function editorPhrases(labels) {
  const phrases = {
    "Indent lines": labels.editorIndentLines,
    "Indentation updated. Preview checks policy compatibility.": labels.editorIndentationUpdated,
    Find: labels.editorFind,
    Replace: labels.editorReplace,
    next: labels.editorNext,
    previous: labels.editorPrevious,
    all: labels.editorAll,
    "match case": labels.editorMatchCase,
    regexp: labels.editorRegexp,
    "by word": labels.editorByWord,
    replace: labels.editorReplace === "Replace" ? undefined : labels.editorReplace,
    "replace all": labels.editorReplaceAll,
    close: labels.editorClose,
    "current match": labels.editorCurrentMatch,
    "on line": labels.editorOnLine,
    "replaced match on line $": labels.editorReplacedMatchOnLine,
    "replaced $ matches": labels.editorReplacedMatches,
    "Go to line": labels.editorGoToLine,
    go: labels.editorGo,
    "Folded lines": labels.editorFoldedLines,
    "Unfolded lines": labels.editorUnfoldedLines,
    to: labels.editorTo,
    "folded code": labels.editorFoldedCode,
    unfold: labels.editorUnfold,
    "Fold line": labels.editorFoldLine,
    "Unfold line": labels.editorUnfoldLine,
    Diagnostics: labels.editorDiagnostics,
    "No diagnostics": labels.editorNoDiagnostics,
    "Selection deleted": labels.editorSelectionDeleted,
    "Control character": labels.editorControlCharacter,
    Completions: labels.editorCompletions,
  };
  return Object.fromEntries(Object.entries(phrases).filter(([, label]) => label));
}
