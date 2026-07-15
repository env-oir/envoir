/*
 * Envoir landing page — small progressive-enhancement behaviors:
 * theme toggle (persisted), scroll reveals, and the hero address readout.
 * No dependencies, no build step.
 */
(function () {
  "use strict";

  var root = document.documentElement;
  var STORAGE_KEY = "envoir-theme";

  /* ---------------- theme toggle ---------------- */
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var toggle = document.getElementById("theme-toggle");
    if (toggle) toggle.setAttribute("aria-checked", theme === "light" ? "true" : "false");
    try { window.dispatchEvent(new Event("envoir:theme-changed")); } catch (e) { /* older browsers */ }
  }

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(STORAGE_KEY); } catch (e) { /* storage disabled */ }
    // dark is the deliberate primary; only a returning visitor's explicit
    // choice moves it to light.
    applyTheme(saved === "light" ? "light" : "dark");

    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(next);
      try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* ignore */ }
    });
  }

  /* ---------------- scroll reveals ---------------- */
  function initReveals() {
    var items = document.querySelectorAll(".reveal");
    if (!items.length) return;

    if (!("IntersectionObserver" in window)) {
      items.forEach(function (el) { el.classList.add("in-view"); });
      return;
    }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });

    items.forEach(function (el) { io.observe(el); });
  }

  /* ---------------- hero address cycling readout ----------------
   * Cycles through the two name@domain flavours (provider-issued,
   * own domain) plus a plus-addressed alias — never the raw key or
   * its word-encoded safety number, which is a verification aid,
   * not an address (see #naming / §3.4.1, §3.9). */
  function initAddress() {
    var el = document.getElementById("address-readout");
    if (!el) return;
    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) return; // leave the static example address, no cycling

    var names = [
      "you@envoir.org",
      "alice@yourbrand.com",
      "sam+news@envoir.org"
    ];
    var idx = 0;
    var cursor = '<span class="cursor">&nbsp;</span>';

    function typeOut(text, cb) {
      var i = 0;
      (function tick() {
        el.innerHTML = text.slice(0, i) + cursor;
        i++;
        if (i <= text.length) {
          setTimeout(tick, 26);
        } else if (cb) {
          setTimeout(cb, 2600);
        }
      })();
    }

    function eraseThenNext() {
      var text = names[idx];
      var i = text.length;
      (function tick() {
        el.innerHTML = text.slice(0, i) + cursor;
        i--;
        if (i >= 0) {
          setTimeout(tick, 14);
        } else {
          idx = (idx + 1) % names.length;
          typeOut(names[idx], eraseThenNext);
        }
      })();
    }

    // start the cycle after the initial static reveal has had a moment on screen
    setTimeout(function () { eraseThenNext(); }, 3200);
  }

  /* ---------------- smooth-scroll for in-page nav (respects reduced motion via CSS) ---------------- */
  function initNavLinks() {
    var links = document.querySelectorAll('a[href^="#"]');
    links.forEach(function (a) {
      a.addEventListener("click", function (e) {
        var id = a.getAttribute("href").slice(1);
        if (!id) return;
        var target = document.getElementById(id);
        if (!target) return;
        e.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        history.pushState(null, "", "#" + id);
      });
    });
  }

  function init() {
    initTheme();
    initReveals();
    initAddress();
    initNavLinks();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
