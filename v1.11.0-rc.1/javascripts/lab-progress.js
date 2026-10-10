// Keeps the training lab's tick-boxes ticked across visits, in this browser only.
// pymdownx.tasklist renders each "- [ ]" as a checkbox; this remembers which ones were ticked,
// keyed by the page and the box's position, and does nothing on pages without task lists.
(function () {
  function boxes() {
    return Array.prototype.slice.call(document.querySelectorAll(".task-list-control input[type=checkbox]"));
  }
  function key() {
    return "pixi-sbom-progress:" + location.pathname;
  }
  function load() {
    try {
      return JSON.parse(localStorage.getItem(key()) || "[]");
    } catch (e) {
      return [];
    }
  }
  function save(list) {
    try {
      localStorage.setItem(key(), JSON.stringify(list));
    } catch (e) {
      // Storage unavailable (a private window, blocked site data): the boxes still tick, they just forget.
    }
  }
  function init() {
    var all = boxes();
    if (!all.length) return;
    var ticked = load();
    all.forEach(function (box, index) {
      box.disabled = false;
      box.checked = ticked.indexOf(index) !== -1;
      box.addEventListener("change", function () {
        save(boxes().map(function (b, i) { return b.checked ? i : -1; }).filter(function (i) { return i !== -1; }));
      });
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
