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
        closeMobileMenu();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        history.pushState(null, "", "#" + id);
      });
    });
  }

  /* ---------------- reading-progress bar ----------------
   * A thin gradient rule tracks how far through the page you are —
   * the instrument-panel readout, driven off scroll via rAF. */
  function initProgress() {
    var bar = document.getElementById("scroll-progress-bar");
    if (!bar) return;
    var ticking = false;
    function update() {
      ticking = false;
      var doc = document.documentElement;
      var max = (doc.scrollHeight - doc.clientHeight) || 1;
      var p = Math.min(1, Math.max(0, (window.scrollY || doc.scrollTop) / max));
      bar.style.transform = "scaleX(" + p + ")";
    }
    window.addEventListener("scroll", function () {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    window.addEventListener("resize", update, { passive: true });
    update();
  }

  /* ---------------- scroll-spy: highlight the section you're reading ----------------
   * Geometry-based: the active section is the one straddling the viewport
   * midline (robust for tall sections, unlike a raw intersection-ratio pick).
   * An IntersectionObserver is used only as a cheap "something changed" trigger,
   * throttled through rAF. */
  function initScrollSpy() {
    var linkEls = document.querySelectorAll('.nav-links a[href^="#"], .mobile-menu a[href^="#"]');
    if (!linkEls.length) return;

    var byId = {};
    linkEls.forEach(function (a) {
      var id = a.getAttribute("href").slice(1);
      (byId[id] = byId[id] || []).push(a);
    });

    var sections = Object.keys(byId)
      .map(function (id) { return document.getElementById(id); })
      .filter(Boolean);
    if (!sections.length) return;

    var current = null;
    function setActive(id) {
      if (id === current) return;
      current = id;
      linkEls.forEach(function (a) { a.classList.remove("active"); });
      if (id && byId[id]) byId[id].forEach(function (a) { a.classList.add("active"); });
    }

    function recompute() {
      var mid = window.innerHeight * 0.5;
      var best = null, bestDist = Infinity;
      for (var i = 0; i < sections.length; i++) {
        var r = sections[i].getBoundingClientRect();
        if (r.top <= mid && r.bottom > mid) { best = sections[i].id; break; } // straddles midline — exact
        var d = r.top > mid ? r.top - mid : mid - r.bottom; // nearest to midline as fallback
        if (d < bestDist) { bestDist = d; best = sections[i].id; }
      }
      setActive(best);
    }

    var ticking = false;
    function onScroll() {
      if (!ticking) { ticking = true; requestAnimationFrame(function () { ticking = false; recompute(); }); }
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    recompute();
  }

  /* ---------------- mobile menu ---------------- */
  var mobileMenu, navToggle;
  function closeMobileMenu() {
    if (!mobileMenu || mobileMenu.hasAttribute("hidden")) return;
    mobileMenu.setAttribute("hidden", "");
    if (navToggle) { navToggle.setAttribute("aria-expanded", "false"); navToggle.setAttribute("aria-label", "Open menu"); }
    var nav = document.querySelector(".site-nav");
    if (nav) nav.classList.remove("nav-open");
  }
  function openMobileMenu() {
    if (!mobileMenu) return;
    mobileMenu.removeAttribute("hidden");
    if (navToggle) { navToggle.setAttribute("aria-expanded", "true"); navToggle.setAttribute("aria-label", "Close menu"); }
    var nav = document.querySelector(".site-nav");
    if (nav) nav.classList.add("nav-open");
  }
  function initMobileMenu() {
    mobileMenu = document.getElementById("mobile-menu");
    navToggle = document.getElementById("nav-toggle");
    if (!mobileMenu || !navToggle) return;
    navToggle.addEventListener("click", function () {
      if (mobileMenu.hasAttribute("hidden")) openMobileMenu(); else closeMobileMenu();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeMobileMenu();
    });
    // if the viewport grows past the mobile breakpoint, ensure the menu is closed
    if (window.matchMedia) {
      var mq = window.matchMedia("(min-width: 860px)");
      var onChange = function (e) { if (e.matches) closeMobileMenu(); };
      if (mq.addEventListener) mq.addEventListener("change", onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
  }

  /* ---------------- count-up for the parity tally ----------------
   * Numbers count up once, when the tally scrolls into view. Honest:
   * these are the real audit figures from §17, just animated in. */
  function initCounters() {
    var nums = document.querySelectorAll(".pt-num");
    if (!nums.length) return;
    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    nums.forEach(function (el) {
      var target = parseInt((el.textContent || "").replace(/[^0-9]/g, ""), 10);
      if (isNaN(target)) return;
      el.setAttribute("data-target", String(target));
    });

    if (reduceMotion || !("IntersectionObserver" in window)) return; // leave real numbers in place

    function run(el) {
      var target = parseInt(el.getAttribute("data-target"), 10);
      if (isNaN(target)) return;
      var dur = 900, start = null;
      el.textContent = "0";
      (function frame(ts) {
        if (start === null) start = ts;
        var t = Math.min(1, (ts - start) / dur);
        var eased = 1 - Math.pow(1 - t, 3);
        el.textContent = String(Math.round(target * eased));
        if (t < 1) requestAnimationFrame(frame);
        else el.textContent = String(target);
      })(performance.now());
    }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { run(e.target); io.unobserve(e.target); }
      });
    }, { threshold: 0.6 });
    nums.forEach(function (el) { io.observe(el); });
  }

  function init() {
    initTheme();
    initReveals();
    initAddress();
    initNavLinks();
    initProgress();
    initScrollSpy();
    initMobileMenu();
    initCounters();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
