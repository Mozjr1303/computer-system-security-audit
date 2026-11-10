/* Portfolio interactions
   1. Mobile navigation
   2. Gentle reveal-on-scroll
   3. Presentation mode: larger content, one section ("slide") at a time,
      Previous / Next across all three pages, keyboard control.
   Everything still works with JavaScript disabled. */
(function () {
  "use strict";

  var root = document.documentElement;
  var body = document.body;
  var STORE_KEY = "va-present";

  function store(value) {
    try { if (value) { sessionStorage.setItem(STORE_KEY, "1"); } else { sessionStorage.removeItem(STORE_KEY); } } catch (e) { /* storage unavailable */ }
  }
  function stored() {
    try { return sessionStorage.getItem(STORE_KEY) === "1"; } catch (e) { return false; }
  }

  /* ---------- 1. Mobile navigation ---------- */
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.getElementById("site-nav");
  function closeNav() {
    if (!nav) { return; }
    nav.classList.remove("is-open");
    if (toggle) { toggle.setAttribute("aria-expanded", "false"); toggle.textContent = "Menu"; }
  }
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.textContent = open ? "Close" : "Menu";
    });
    nav.addEventListener("click", function (e) { if (e.target.closest("a")) { closeNav(); } });
  }

  /* ---------- 2. Reveal on scroll ---------- */
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var items = document.querySelectorAll("[data-reveal]");
  if (!reduce && "IntersectionObserver" in window && items.length) {
    root.classList.add("reveal-ready");
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) { entry.target.classList.add("is-visible"); io.unobserve(entry.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    items.forEach(function (el) { io.observe(el); });
  }

  /* ---------- 3. Presentation mode ---------- */
  var slides = Array.prototype.slice.call(document.querySelectorAll("[data-slide]"));
  var prevPage = body.getAttribute("data-prev");
  var nextPage = body.getAttribute("data-next");
  var presentBtn = document.querySelector(".present-btn");

  // Build the floating deck bar
  var bar = document.createElement("div");
  bar.className = "deck-bar";
  bar.setAttribute("role", "toolbar");
  bar.setAttribute("aria-label", "Presentation controls");
  bar.innerHTML =
    '<button type="button" data-act="prev" aria-label="Previous section">← Previous</button>' +
    '<span class="deck-bar__pos" aria-live="polite"></span>' +
    '<button type="button" data-act="next" aria-label="Next section">Next →</button>' +
    '<button type="button" data-act="exit" class="deck-bar__exit" aria-label="Exit presentation mode">Exit</button>';
  body.appendChild(bar);
  var posEl = bar.querySelector(".deck-bar__pos");
  var prevBtn = bar.querySelector('[data-act="prev"]');
  var nextBtn = bar.querySelector('[data-act="next"]');

  function headerOffset() {
    var mh = document.querySelector(".masthead");
    return mh ? mh.offsetHeight : 0;
  }

  function currentIndex() {
    var line = headerOffset() + window.innerHeight * 0.3;
    var idx = 0;
    for (var i = 0; i < slides.length; i++) {
      if (slides[i].getBoundingClientRect().top <= line) { idx = i; }
    }
    return idx;
  }

  function slideTitle(el) {
    return el.getAttribute("data-slide") || "";
  }

  function updateBar() {
    if (!slides.length) { return; }
    var i = currentIndex();
    posEl.innerHTML = "<b>" + (i + 1) + " / " + slides.length + "</b> · " + slideTitle(slides[i]);
    prevBtn.disabled = i === 0 && !prevPage;
    nextBtn.disabled = i === slides.length - 1 && !nextPage;
    prevBtn.textContent = (i === 0 && prevPage) ? "← Previous page" : "← Previous";
    nextBtn.textContent = (i === slides.length - 1 && nextPage) ? "Next page →" : "Next →";
  }

  function goTo(i) {
    var el = slides[i];
    if (!el) { return; }
    var top = el.getBoundingClientRect().top + window.pageYOffset - headerOffset();
    window.scrollTo({ top: i === 0 ? 0 : top, behavior: reduce ? "auto" : "smooth" });
  }

  function next() {
    var i = currentIndex();
    // Tall slide: reveal the rest of it before moving on
    var rect = slides[i] ? slides[i].getBoundingClientRect() : null;
    if (rect && rect.bottom > window.innerHeight + 60) {
      window.scrollBy({ top: Math.min(rect.bottom - window.innerHeight + 24, window.innerHeight * 0.8), behavior: reduce ? "auto" : "smooth" });
      return;
    }
    if (i < slides.length - 1) { goTo(i + 1); }
    else if (nextPage) { window.location.href = nextPage; }
  }
  function prev() {
    var i = currentIndex();
    // If we are part-way into a tall slide, go back to its start first
    var top = slides[i] ? slides[i].getBoundingClientRect().top - headerOffset() : 0;
    if (top < -40) { goTo(i); return; }
    if (i > 0) { goTo(i - 1); }
    else if (prevPage) { window.location.href = prevPage + "#last"; }
  }

  function setPresent(on) {
    root.classList.toggle("present", on);
    store(on);
    if (presentBtn) {
      presentBtn.setAttribute("aria-pressed", on ? "true" : "false");
      presentBtn.querySelector(".present-btn__label").textContent = on ? "Presenting" : "Present";
    }
    closeNav();
    updateBar();
  }

  if (presentBtn) {
    presentBtn.addEventListener("click", function () { setPresent(!root.classList.contains("present")); });
  }
  bar.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) { return; }
    var act = b.getAttribute("data-act");
    if (act === "next") { next(); }
    else if (act === "prev") { prev(); }
    else if (act === "exit") { setPresent(false); }
  });

  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) { return; }
    if (e.ctrlKey || e.metaKey || e.altKey) { return; }

    if (e.key === "Escape") {
      if (nav && nav.classList.contains("is-open")) { closeNav(); if (toggle) { toggle.focus(); } return; }
      if (root.classList.contains("present")) { setPresent(false); }
      return;
    }
    if (e.key === "p" || e.key === "P") { setPresent(!root.classList.contains("present")); return; }
    if (!root.classList.contains("present")) { return; }

    if (e.key === "ArrowRight" || e.key === "PageDown" || (e.key === " " && !e.shiftKey)) {
      e.preventDefault(); next();
    } else if (e.key === "ArrowLeft" || e.key === "PageUp" || (e.key === " " && e.shiftKey)) {
      e.preventDefault(); prev();
    } else if (e.key === "Home") {
      e.preventDefault(); goTo(0);
    } else if (e.key === "End") {
      e.preventDefault(); goTo(slides.length - 1);
    }
  });

  var ticking = false;
  window.addEventListener("scroll", function () {
    if (ticking || !root.classList.contains("present")) { return; }
    ticking = true;
    window.requestAnimationFrame(function () { updateBar(); ticking = false; });
  }, { passive: true });

  // Start in presentation mode if requested by URL (?present) or carried over from the previous page
  var params = new URLSearchParams(window.location.search);
  if (params.has("present") || stored()) { setPresent(true); }
  if (window.location.hash === "#last" && slides.length) {
    window.addEventListener("load", function () { goTo(slides.length - 1); });
  }
})();
