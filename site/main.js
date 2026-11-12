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
      if (focus) {
        tab.focus();
        tab.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
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

  // ---- Downloads: pick the right file for this OS and CPU ----------------
  // Reads the latest release from the GitHub API. Without it (offline, rate
  // limited), every download link keeps pointing at the releases page.
  var REPO = "portvex/bxplore";

  function detectPlatform() {
    var ua = navigator.userAgent || "";
    var uad = navigator.userAgentData;
    var p = (uad && uad.platform) || "";
    var os = null;
    if (/Android|iPhone|iPad|iPod/i.test(ua) || p === "Android" ||
        (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) os = null; // phone or tablet
    else if (p === "Windows" || /Windows/i.test(ua)) os = "windows";
    else if (p === "macOS" || /Mac OS X|Macintosh/i.test(ua)) os = "macos";
    else if (p === "Linux" || p === "Chrome OS" || /Linux|X11|CrOS/i.test(ua)) os = "linux";

    var arch = /aarch64|arm64|armv8/i.test(ua) ? "arm64" : "x64";
    if (uad && uad.getHighEntropyValues) {
      return uad.getHighEntropyValues(["architecture"]).then(function (v) {
        if (v.architecture === "arm") arch = "arm64";
        else if (v.architecture === "x86") arch = "x64";
        return { os: os, arch: arch };
      }, function () { return { os: os, arch: arch }; });
    }
    return Promise.resolve({ os: os, arch: arch });
  }

  function fetchRelease() {
    var key = "bxplore-release";
    try {
      var cached = JSON.parse(sessionStorage.getItem(key) || "null");
      if (cached && Date.now() - cached.t < 10 * 60 * 1000) return Promise.resolve(cached.d);
    } catch (e) {}
    return fetch("https://api.github.com/repos/" + REPO + "/releases/latest", {
      headers: { Accept: "application/vnd.github+json" }
    }).then(function (r) {
      if (!r.ok) throw new Error("GitHub API " + r.status);
      return r.json();
    }).then(function (d) {
      var slim = {
        tag: d.tag_name,
        assets: (d.assets || []).map(function (a) { return { name: a.name, url: a.browser_download_url, size: a.size }; })
      };
      try { sessionStorage.setItem(key, JSON.stringify({ t: Date.now(), d: slim })); } catch (e) {}
      return slim;
    });
  }

  // bxplore-<version>-<os>-<arch>[-portable|-setup][.ext]
  var ASSET_RE = /^bxplore-(.+?)-(windows|macos|linux)-(x64|arm64|x86_64|aarch64|universal)(?:-(portable|setup))?(\.zip|\.exe|\.dmg|\.flatpak|\.tar\.gz)?$/;
  var ARCH = { x64: "x64", x86_64: "x64", arm64: "arm64", aarch64: "arm64", universal: "universal" };
  var ARCH_LABEL = { x64: "x64", arm64: "ARM64", universal: "Intel + Apple Silicon" };
  var OS_LABEL = { windows: "Windows", macos: "macOS", linux: "Linux" };

  function describe(a) {
    var m = ASSET_RE.exec(a.name);
    if (!m) return null;
    var ext = m[5] || "", kind, rank;
    if (m[4] === "setup") { kind = "Installer"; rank = 0; }
    else if (m[4] === "portable") { kind = "Portable zip"; rank = 1; }
    else if (ext === ".dmg") { kind = "Disk image (.dmg)"; rank = 0; }
    else if (ext === ".tar.gz") { kind = "Executable (.tar.gz)"; rank = 0; }
    else if (ext === ".flatpak") { kind = "Flatpak"; rank = 2; }
    else { kind = "Executable"; rank = 1; }
    return { name: a.name, url: a.url, size: a.size, os: m[2], arch: ARCH[m[3]], kind: kind, rank: rank };
  }

  function mb(bytes) { return (bytes / 1048576).toFixed(1) + " MB"; }

  // The file a "Download" button gives for this platform.
  function pick(files, plat) {
    var cands = files.filter(function (f) {
      return f.os === plat.os && f.rank === 0 && (f.arch === plat.arch || f.arch === "universal");
    });
    return cands[0] || null;
  }

  function renderAssets(files, best) {
    document.querySelectorAll("[data-assets]").forEach(function (box) {
      var os = box.getAttribute("data-assets");
      var list = files.filter(function (f) { return f.os === os; }).sort(function (a, b) {
        return a.arch === b.arch ? a.rank - b.rank : (a.arch === "x64" ? -1 : 1);
      });
      if (!list.length) return;
      var ul = document.createElement("ul");
      ul.className = "asset-list";
      list.forEach(function (f) {
        var li = document.createElement("li");
        if (best && f.name === best.name) li.className = "best";
        var a = document.createElement("a");
        a.href = f.url;
        a.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m0 0-5-5m5 5 5-5M4 17v3h16v-3"/></svg>';
        var main = document.createElement("span");
        main.className = "asset-main";
        main.textContent = f.kind;
        var arch = document.createElement("span");
        arch.className = "asset-arch";
        arch.textContent = ARCH_LABEL[f.arch];
        var meta = document.createElement("span");
        meta.className = "asset-meta";
        meta.textContent = f.name + " · " + mb(f.size);
        main.appendChild(arch);
        a.appendChild(main);
        a.appendChild(meta);
        if (best && f.name === best.name) {
          var b = document.createElement("span");
          b.className = "asset-badge";
          b.textContent = "Recommended for you";
          a.appendChild(b);
        }
        li.appendChild(a);
        ul.appendChild(li);
      });
      box.replaceChildren(ul);
    });
  }

  function updateButtons(rel, best, plat) {
    var buttons = document.querySelectorAll("[data-download]");
    var meta = document.querySelector("[data-download-meta]");
    if (best) {
      buttons.forEach(function (b) {
        b.href = best.url;
        b.querySelector("[data-download-label]").textContent = "Download for " + OS_LABEL[plat.os];
      });
      if (meta) {
        var what = best.arch === "universal" ? best.kind : ARCH_LABEL[best.arch] + " " + best.kind.toLowerCase();
        meta.innerHTML = "";
        meta.appendChild(document.createTextNode(rel.tag + " · " + what + " · " + mb(best.size) + " · "));
        var other = document.createElement("a");
        other.href = "#install";
        other.textContent = "other platforms";
        meta.appendChild(other);
      }
    } else if (!plat.os) {
      // Phone or tablet: there is nothing to run here, so show the choices.
      buttons.forEach(function (b) { b.href = "#install"; });
    }
  }

  var tabFor = { windows: "tab-win", macos: "tab-mac", linux: "tab-linux" };
  detectPlatform().then(function (plat) {
    if (plat.os && tabFor[plat.os]) document.getElementById(tabFor[plat.os]).click();
    return fetchRelease().then(function (rel) {
      var files = rel.assets.map(describe).filter(Boolean);
      var best = pick(files, plat);
      renderAssets(files, best);
      updateButtons(rel, best, plat);
      var sums = rel.assets.filter(function (a) { return a.name === "SHA256SUMS"; })[0];
      var sumsEl = document.querySelector("[data-sums]");
      if (sums && sumsEl) {
        var link = document.createElement("a");
        link.href = sums.url;
        link.textContent = "SHA256SUMS";
        sumsEl.replaceChildren(link);
      }
    });
  }).catch(function () { /* keep the releases page links */ });

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
