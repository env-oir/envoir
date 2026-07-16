/*
 * Envoir docs viewer — renders the shared docs/*.md corpus (mirrored into
 * docs-src/ at ./site) client-side with js/markdown.js. No build step, no
 * server-side routing: navigation is hash-based (#/doc-id[#fragment]) so the
 * whole thing works from a plain static file server, and reloads land back
 * on the same page.
 */
(function () {
  "use strict";

  var GITHUB_REPO = "https://github.com/env-oir/envoir/blob/main/";

  /* One entry per docs-src/*.md file. `repoPath` is that file's real path in
   * the envoir repo (docs/...), used to resolve the relative links inside the
   * rendered markdown back to either another doc in this manifest (internal
   * route) or a best-effort GitHub link (external, so nothing renders as a
   * dead relative href). */
  var MANIFEST = [
    { id: "index", title: "Overview", file: "index.md", repoPath: "docs/index.md", group: "Start" },
    { id: "getting-started", title: "Getting started", file: "getting-started.md", repoPath: "docs/getting-started.md", group: "Start" },
    { id: "architecture", title: "Architecture", file: "architecture.md", repoPath: "docs/architecture.md", group: "Start" },
    { id: "roadmap", title: "Roadmap", file: "roadmap.md", repoPath: "docs/roadmap.md", group: "Start" },

    { id: "protocol", title: "Protocol", file: "protocol.md", repoPath: "docs/protocol.md", group: "Protocol & security" },
    { id: "privacy", title: "Privacy & threat model", file: "privacy.md", repoPath: "docs/privacy.md", group: "Protocol & security" },
    { id: "security", title: "Security", file: "security.md", repoPath: "docs/security.md", group: "Protocol & security" },

    { id: "mail", title: "Mail", file: "features/mail.md", repoPath: "docs/features/mail.md", group: "Features" },
    { id: "chat", title: "Chat", file: "features/chat.md", repoPath: "docs/features/chat.md", group: "Features" },
    { id: "files", title: "Files", file: "features/files.md", repoPath: "docs/features/files.md", group: "Features" },
    { id: "identity", title: "Identity", file: "features/identity.md", repoPath: "docs/features/identity.md", group: "Features" },
    { id: "transport-traceability", title: "Transport provenance", file: "features/transport-traceability.md", repoPath: "docs/features/transport-traceability.md", group: "Features" },
    { id: "self-hosting", title: "Self-hosting", file: "features/self-hosting.md", repoPath: "docs/features/self-hosting.md", group: "Features" },

    { id: "faq", title: "FAQ", file: "faq.md", repoPath: "docs/faq.md", group: "More" },
    { id: "contributing", title: "Contributing", file: "contributing.md", repoPath: "docs/contributing.md", group: "More" },
    { id: "screenshots", title: "Screenshot tooling", file: "SCREENSHOTS.md", repoPath: "docs/SCREENSHOTS.md", group: "More" }
  ];

  var BY_ID = {};
  var BY_REPOPATH = {};
  MANIFEST.forEach(function (d) {
    BY_ID[d.id] = d;
    BY_REPOPATH[d.repoPath] = d;
  });

  // Screenshots referenced by docs/features/*.md, flattened into assets/screens/.
  var KNOWN_SCREENS = {
    "mail-dark.png": "assets/screens/mail-dark.png",
    "chat-dark.png": "assets/screens/chat-dark.png",
    "files-dark.png": "assets/screens/files-dark.png",
    "identity-dark.png": "assets/screens/identity-dark.png",
    "path-graph.png": "assets/screens/path-graph.png"
  };

  var contentEl = document.getElementById("doc-content");
  var sidebarEl = document.getElementById("doc-sidebar");
  var tocEl = document.getElementById("doc-toc");
  var crumbEl = document.getElementById("doc-breadcrumb");
  var cache = Object.create(null);

  /* ---------------- path resolution for cross-doc links/images ---------------- */

  function normalizeRepoPath(fromRepoPath, relHref) {
    var baseParts = fromRepoPath.split("/");
    baseParts.pop(); // drop filename, keep directory
    var relParts = relHref.split("/");
    relParts.forEach(function (part) {
      if (part === "." || part === "") return;
      if (part === "..") baseParts.pop();
      else baseParts.push(part);
    });
    return baseParts.join("/");
  }

  function rewriteLinks(root, currentDoc) {
    root.querySelectorAll("a[href]").forEach(function (a) {
      var href = a.getAttribute("href");
      if (/^https?:\/\//.test(href) || href.indexOf("mailto:") === 0) {
        a.target = "_blank";
        a.rel = "noopener";
        return;
      }
      if (href.charAt(0) === "#") {
        return; // in-page anchor, leave as-is
      }
      var hashIdx = href.indexOf("#");
      var pathPart = hashIdx === -1 ? href : href.slice(0, hashIdx);
      var fragment = hashIdx === -1 ? "" : href.slice(hashIdx);
      var normalized = normalizeRepoPath(currentDoc.repoPath, pathPart);
      var target = BY_REPOPATH[normalized];
      if (target) {
        a.setAttribute("href", "#/" + target.id + fragment);
      } else {
        a.setAttribute("href", GITHUB_REPO + normalized);
        a.target = "_blank";
        a.rel = "noopener";
      }
    });

    root.querySelectorAll("img[src]").forEach(function (img) {
      var src = img.getAttribute("src");
      if (/^https?:\/\//.test(src)) return;
      var base = src.split("/").pop();
      if (KNOWN_SCREENS[base]) {
        img.setAttribute("src", KNOWN_SCREENS[base]);
      }
      img.classList.add("doc-img");
    });
  }

  /* ---------------- sidebar ---------------- */

  function buildSidebar() {
    var groups = [];
    var seen = Object.create(null);
    MANIFEST.forEach(function (d) {
      if (!seen[d.group]) {
        seen[d.group] = { name: d.group, docs: [] };
        groups.push(seen[d.group]);
      }
      seen[d.group].docs.push(d);
    });

    sidebarEl.innerHTML = groups
      .map(function (g) {
        var items = g.docs
          .map(function (d) {
            return (
              '<a href="#/' + d.id + '" data-doc-id="' + d.id + '">' + d.title + "</a>"
            );
          })
          .join("");
        return '<div class="doc-nav-group"><h4>' + g.name + "</h4>" + items + "</div>";
      })
      .join("");
  }

  function setActiveSidebar(id) {
    sidebarEl.querySelectorAll("a[data-doc-id]").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-doc-id") === id);
    });
  }

  /* ---------------- on-this-page mini TOC ---------------- */

  function buildToc() {
    var heads = contentEl.querySelectorAll("h2, h3");
    if (!heads.length) {
      tocEl.innerHTML = "";
      tocEl.hidden = true;
      return;
    }
    tocEl.hidden = false;
    var html = ['<h4>On this page</h4><nav>'];
    heads.forEach(function (h) {
      var cls = h.tagName === "H3" ? " class=\"sub\"" : "";
      html.push('<a href="#' + h.id + '"' + cls + ">" + h.textContent + "</a>");
    });
    html.push("</nav>");
    tocEl.innerHTML = html.join("");
  }

  /* ---------------- breadcrumb / prev-next ---------------- */

  function buildBreadcrumb(doc) {
    var idx = MANIFEST.indexOf(doc);
    var prev = MANIFEST[idx - 1];
    var next = MANIFEST[idx + 1];
    var parts = [
      '<span class="crumb-group">' + doc.group + "</span>",
      '<span class="crumb-sep">/</span>',
      "<span>" + doc.title + "</span>"
    ];
    crumbEl.innerHTML = parts.join("");

    var nav = document.getElementById("doc-prevnext");
    var bits = [];
    if (prev) bits.push('<a class="pn-link pn-prev" href="#/' + prev.id + '">&larr; ' + prev.title + "</a>");
    else bits.push("<span></span>");
    if (next) bits.push('<a class="pn-link pn-next" href="#/' + next.id + '">' + next.title + " &rarr;</a>");
    nav.innerHTML = bits.join("");
  }

  /* ---------------- render pipeline ---------------- */

  function fetchDoc(doc) {
    if (cache[doc.id]) return Promise.resolve(cache[doc.id]);
    return fetch("docs-src/" + doc.file)
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then(function (text) {
        cache[doc.id] = text;
        return text;
      });
  }

  function renderDoc(id, fragment) {
    var doc = BY_ID[id] || BY_ID.index;
    fetchDoc(doc)
      .then(function (md) {
        contentEl.innerHTML = EnvoirMD.render(md);
        rewriteLinks(contentEl, doc);
        buildToc();
        buildBreadcrumb(doc);
        setActiveSidebar(doc.id);
        document.title = doc.title + " — Envoir docs";
        closeMobileSidebar();
        if (fragment) {
          var target = document.getElementById(fragment);
          if (target) {
            requestAnimationFrame(function () { target.scrollIntoView({ block: "start" }); });
            return;
          }
        }
        contentEl.scrollTop = 0;
        window.scrollTo(0, 0);
      })
      .catch(function (err) {
        contentEl.innerHTML =
          '<div class="doc-error"><h2>Couldn’t load this page</h2><p>' +
          EnvoirMD.escapeHtml(String(err && err.message ? err.message : err)) +
          "</p></div>";
      });
  }

  function route() {
    var hash = location.hash.replace(/^#\/?/, "");
    var hashIdx = hash.indexOf("#");
    var id = hashIdx === -1 ? hash : hash.slice(0, hashIdx);
    var fragment = hashIdx === -1 ? "" : hash.slice(hashIdx + 1);
    if (!id) id = "index";
    renderDoc(id, fragment);
  }

  /* ---------------- mobile sidebar toggle ---------------- */

  function closeMobileSidebar() {
    document.body.classList.remove("docs-nav-open");
  }

  function initMobileToggle() {
    var btn = document.getElementById("doc-nav-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      document.body.classList.toggle("docs-nav-open");
    });
    var scrim = document.getElementById("doc-nav-scrim");
    if (scrim) scrim.addEventListener("click", closeMobileSidebar);
  }

  function init() {
    buildSidebar();
    initMobileToggle();
    window.addEventListener("hashchange", route);
    route();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
