// Light/dark theme. Loaded as a classic script in <head> so the page never
// flashes the wrong colors. Follows the system until the user picks one.
(function () {
  var KEY = "cc-theme";
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function stored() {
    try { return localStorage.getItem(KEY); } catch (_error) { return null; }
  }

  function apply(theme) {
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
  }

  apply(stored() || (media && media.matches ? "dark" : "light"));

  if (media && media.addEventListener) {
    media.addEventListener("change", function (event) {
      if (!stored()) apply(event.matches ? "dark" : "light");
    });
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("[data-theme-toggle]");
    if (!button) return;
    var next = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem(KEY, next); } catch (_error) { /* private mode */ }
    apply(next);
  });
})();
