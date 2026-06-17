/* Theme: set before first paint (this file is loaded synchronously in <head>,
   so the attribute is in place before the body renders — no flash), then wire
   the toggle once the DOM is ready. Default dark, matching the tool family. */
(function () {
  var KEY = "gpol-theme";
  function get() {
    try { return localStorage.getItem(KEY) || "dark"; } catch (e) { return "dark"; }
  }
  function apply(t) { document.documentElement.setAttribute("data-theme", t); }

  apply(get());

  function updateIcons() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    var d = document.getElementById("theme-icon-dark");
    var l = document.getElementById("theme-icon-light");
    if (d) d.style.display = dark ? "none" : "block";
    if (l) l.style.display = dark ? "block" : "none";
  }

  function wire() {
    updateIcons();
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (e) {}
      updateIcons();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
