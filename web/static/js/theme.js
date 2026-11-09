/* Runs in <head> before first paint so there is no flash of the wrong theme. */
(function () {
  try {
    var t = localStorage.getItem("sl-theme");
    if (t === "dark" || t === "light") document.documentElement.setAttribute("data-theme", t);
  } catch (e) {}
})();
