/* Small progressive enhancements. The site works without JavaScript. */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  // ---- behaviours that attach to elements; run again after live content is swapped in ----
  function init(root) {
    $$("[data-toggle-password]", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var input = document.getElementById(btn.getAttribute("data-toggle-password"));
        var show = input.type === "password"; input.type = show ? "text" : "password"; btn.textContent = show ? "Hide" : "Show";
      });
    });
    $$(".flash button", root).forEach(function (b) { b.addEventListener("click", function () { b.parentNode.remove(); }); });
    $$("form[data-confirm]", root).forEach(function (f) {
      f.addEventListener("submit", function (e) { if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault(); });
    });
    $$("form", root).forEach(function (f) {
      f.addEventListener("submit", function () {
        $$("button[type=submit]", f).forEach(function (b) { setTimeout(function () { b.disabled = true; }, 0); });
      });
    });
    var chat = $(".chat", root); if (chat) chat.scrollTop = chat.scrollHeight;

    // password strength meter (length matters most; the server applies the real rules)
    $$("[data-meter]", root).forEach(function (input) {
      var box = document.createElement("div"); box.className = "meter m0"; box.setAttribute("aria-live", "polite");
      box.innerHTML = '<span class="bar"></span><em></em>';
      (input.closest(".field") || input.parentNode).appendChild(box);
      var label = $("em", box);
      input.addEventListener("input", function () {
        var v = input.value, kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (r) { return r.test(v); }).length;
        var level = 0, text = "";
        if (v.length) { level = 1; text = "Too short"; }
        if (v.length >= 12) { level = 2; text = "OK"; }
        if (v.length >= 12 && kinds >= 3) { level = 3; text = "Good"; }
        if (v.length >= 16) { level = 4; text = "Strong"; }
        if (v.length > 72) { level = 1; text = "Too long (72 max)"; }
        box.className = "meter m" + level; label.textContent = text;
      });
    });
    $$("[data-suggest]", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*?-_", out = "", buf = new Uint32Array(16);
        window.crypto.getRandomValues(buf);
        for (var i = 0; i < buf.length; i++) out += chars.charAt(buf[i] % chars.length);
        btn.getAttribute("data-suggest").split(",").forEach(function (id) {
          var el = document.getElementById(id); if (el) { el.value = out; el.type = "text"; el.dispatchEvent(new Event("input")); }
        });
        btn.textContent = "Suggested - write it down, then continue";
      });
    });
    // "Other (type your own)" service
    var cat = $("#category", root), custom = $("[data-custom-service]", root);
    if (cat && custom) cat.addEventListener("change", function () { custom.classList.toggle("hide", cat.value !== "__custom__"); });
  }
  init(document);

  // Theme toggle
  var tbtn = $("#theme-toggle");
  if (tbtn) tbtn.addEventListener("click", function () {
    var cur = document.documentElement.getAttribute("data-theme");
    var dark = cur ? cur === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    var next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("sl-theme", next); } catch (e) {}
  });

  // Mobile nav + account menu
  var burger = $("#burger"), nav = $(".nav");
  if (burger) burger.addEventListener("click", function () {
    var open = nav.classList.toggle("open"); burger.setAttribute("aria-expanded", open);
  });
  $$(".menu > button").forEach(function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation(); var m = b.parentNode, open = m.classList.toggle("open"); b.setAttribute("aria-expanded", open);
    });
  });
  document.addEventListener("click", function () { $$(".menu.open").forEach(function (m) { m.classList.remove("open"); }); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") $$(".menu.open").forEach(function (m) { m.classList.remove("open"); }); });

  // Provider-only fields on sign-up
  var role = $$("input[name=role]");
  function syncRole() {
    var provider = role.some(function (r) { return r.checked && r.value === "provider"; });
    $$("[data-provider-only]").forEach(function (el) { el.classList.toggle("hide", !provider); });
  }
  role.forEach(function (r) { r.addEventListener("change", syncRole); }); if (role.length) syncRole();

  setTimeout(function () { $$(".flash-ok").forEach(function (f) { f.remove(); }); }, 6000);

  // Live job tracking: refresh the page content every few seconds while nobody is typing.
  var live = $("[data-live]");
  var seconds = live ? parseInt(live.getAttribute("data-live"), 10) : 0;
  if (live && seconds > 0) {
    setInterval(function () {
      if (document.hidden) return;
      var a = document.activeElement;
      if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return;
      var typing = $$("input:not([type=hidden]):not([type=radio]):not([type=checkbox]), textarea", live).some(function (i) { return i.value; });
      if (typing || $$("details[open]", live).length) return;
      fetch(window.location.href, { credentials: "same-origin" }).then(function (r) { return r.ok ? r.text() : null; }).then(function (html) {
        if (!html) return;
        var fresh = new DOMParser().parseFromString(html, "text/html").querySelector("[data-live]");
        if (fresh && fresh.innerHTML !== live.innerHTML) { live.innerHTML = fresh.innerHTML; init(live); }
      }).catch(function () {});
    }, seconds * 1000);
  }
})();
