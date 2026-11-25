/* Share the revision note across the policy editor's separate forms. */
(function () {
  "use strict";

  const editor = document.querySelector('[data-tab-scope="policies"]');
  const summary = editor.querySelector("#top-summary");
  const advancedSummary = editor.querySelector("#raw-summary");

  summary.addEventListener("input", () => { advancedSummary.value = summary.value; });
  advancedSummary.addEventListener("input", () => { summary.value = advancedSummary.value; });

  editor.addEventListener("formdata", event => {
    // Guided forms already carry one hidden summary field. Replace its rendered snapshot.
    if (event.target.elements.namedItem("summary")?.type === "hidden") {
      event.formData.set("summary", summary.value);
    }
  });
})();
