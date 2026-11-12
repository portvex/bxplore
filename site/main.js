// bxplore landing page behaviour: theme toggle, screenshot gallery, lightbox,
// install tabs, copy buttons, hex background and scroll reveal.
(function () {
  "use strict";

  var root = document.documentElement;
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  root.classList.add("js");

  // ---- Theme -------------------------------------------------------------
  var toggle = document.getElementById("theme-toggle");
  function syncToggle() {
    var dark = root.dataset.theme !== "light";
    toggle.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", dark ? "#0b0e17" : "#f7f8fc");
  }
  toggle.addEventListener("click", function () {
    root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem("bxplore-theme", root.dataset.theme); } catch (e) {}
    syncToggle();
  });
  syncToggle();

  // ---- Generic tab lists (arrow keys move between tabs) --------------------
  function tablist(list, onSelect) {
    var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
      });
      if (focus) tab.focus();
      tab.scrollIntoView({ block: "nearest", inline: "nearest" });
      onSelect(tab);
    }
    tabs.forEach(function (t, i) {
      t.tabIndex = t.getAttribute("aria-selected") === "true" ? 0 : -1;
      t.addEventListener("click", function () { select(t, false); });
      t.addEventListener("keydown", function (e) {
        var n = null;
        if (e.key === "ArrowRight") n = tabs[(i + 1) % tabs.length];
        else if (e.key === "ArrowLeft") n = tabs[(i - 1 + tabs.length) % tabs.length];
        else if (e.key === "Home") n = tabs[0];
        else if (e.key === "End") n = tabs[tabs.length - 1];
        if (n) { e.preventDefault(); select(n, true); }
      });
    });
  }

  // ---- Screenshot gallery ------------------------------------------------
  var shots = [
    { file: "pe-headers.png", title: "PE optional header",
      caption: "The selected field is highlighted in the hex panel below the table.",
      alt: "PE optional header with the selected field highlighted in the hex panel" },
    { file: "pe-imports.png", title: "Imports of one module",
      caption: "Every function imported from kernel32.dll, with its thunk, IAT RVA and hint.",
      alt: "PE imports table for one module" },
    { file: "pe-resources.png", title: "Resources, with an icon preview",
      caption: "Icons, bitmaps, version info, manifests and string tables are previewed, and can be replaced.",
      alt: "PE resources tree with an icon preview" },
    { file: "disassembler.png", title: "Disassembler at the entry point",
      caption: "x86, x64, ARM and ARM64, with import names and string literals shown as comments.",
      alt: "Disassembler view at the program entry point" },
    { file: "elf-sections.png", title: "ELF section headers (light theme)",
      caption: "ELF section headers in the light theme.",
      alt: "ELF section headers in the light theme" },
    { file: "macho-signature.png", title: "Mach-O code signature (light theme)",
      caption: "Every code page hash is checked against the file.",
      alt: "Mach-O code signature with the page hashes checked" }
  ];
  var shotImg = document.getElementById("shot-img");
  var shotTitle = document.getElementById("shot-title");
  var shotCaption = document.getElementById("shot-caption");

  // Preload the other screenshots once the page is idle so switching is instant.
  window.addEventListener("load", function () {
    shots.forEach(function (s) { var i = new Image(); i.src = "assets/screenshots/" + s.file; });
  });

  var galleryTabs = document.querySelector("#screens .tabs");
  tablist(galleryTabs, function (tab) {
    var s = shots[Number(tab.dataset.shot)];
    if (!s) return;
    function swap() {
      shotImg.src = "assets/screenshots/" + s.file;
      shotImg.alt = s.alt;
      shotTitle.textContent = s.title;
      shotCaption.textContent = s.caption;
      shotImg.classList.remove("fading");
    }
    if (reduceMotion) { swap(); return; }
    shotImg.classList.add("fading");
    setTimeout(swap, 180);
  });

  // ---- Lightbox ----------------------------------------------------------
  var lightbox = document.getElementById("lightbox");
  var lbImg = lightbox.querySelector("img");
  function openLightbox(src, alt) {
    if (typeof lightbox.showModal !== "function") { window.open(src, "_blank"); return; }
    lbImg.src = src; lbImg.alt = alt;
    lightbox.showModal();
  }
  document.querySelector(".shot-zoom").addEventListener("click", function () {
    openLightbox(shotImg.src, shotImg.alt);
  });
  document.querySelector(".hero-shot img").addEventListener("click", function () {
    openLightbox(this.src, this.alt);
  });
  document.querySelector(".hero-shot img").style.cursor = "zoom-in";
  lightbox.querySelector(".lightbox-close").addEventListener("click", function () { lightbox.close(); });
  lightbox.addEventListener("click", function (e) { if (e.target === lightbox) lightbox.close(); });

  // ---- Install tabs ------------------------------------------------------
  tablist(document.querySelector("#install .tabs"), function (tab) {
    document.querySelectorAll("#install .pane").forEach(function (p) {
      p.hidden = p.id !== tab.getAttribute("aria-controls");
    });
  });

  // ---- Copy buttons ------------------------------------------------------
  document.querySelectorAll(".copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.parentElement.querySelector("code").textContent;
      function done(ok) {
        btn.textContent = ok ? "Copied" : "Copy failed";
        btn.classList.toggle("done", ok);
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1600);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      } else {
        done(false);
      }
    });
  });

  // ---- Hex dump background ----------------------------------------------
  var field = document.querySelector(".hexfield");
  if (field) {
    var hex = "0123456789abcdef";
    // Bytes of an MZ/PE header give the motif a recognisable start.
    var seed = [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
                0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    var rows = 34, cols = 32, cells = [];
    var frag = document.createDocumentFragment();
    for (var r = 0; r < rows; r++) {
      var line = document.createElement("div");
      var off = (r * cols).toString(16).padStart(8, "0") + "  ";
      line.appendChild(document.createTextNode(off));
      for (var c = 0; c < cols; c++) {
        var idx = r * cols + c;
        var b = idx < seed.length ? seed[idx] : (Math.random() < 0.35 ? 0 : Math.floor(Math.random() * 256));
        var span = document.createElement("span");
        span.textContent = hex[b >> 4] + hex[b & 15];
        line.appendChild(span);
        line.appendChild(document.createTextNode(c === 15 ? "  " : " "));
        cells.push(span);
      }
      frag.appendChild(line);
    }
    field.appendChild(frag);

    if (!reduceMotion) {
      // Highlight a few random bytes at a time, like a cursor scanning the file.
      setInterval(function () {
        if (document.hidden) return;
        for (var k = 0; k < 4; k++) {
          var cell = cells[Math.floor(Math.random() * cells.length)];
          cell.classList.add("hl");
          (function (el) { setTimeout(function () { el.classList.remove("hl"); }, 1400); })(cell);
        }
      }, 450);
    }
  }

  // ---- Scroll reveal -----------------------------------------------------
  var revealed = document.querySelectorAll(".reveal");
  if (reduceMotion || !("IntersectionObserver" in window)) {
    revealed.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    revealed.forEach(function (el) { io.observe(el); });
  }
})();
