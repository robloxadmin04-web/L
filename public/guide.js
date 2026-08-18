/* guide.js - Solaries onboarding tour engine
   Lightweight, dependency-free spotlight tour. Each page defines its own
   step list and calls SolariesGuide.init({ page, steps }). This file only
   reads the DOM (querySelector) and never touches app logic, auth, or
   any network request - purely a UI layer. */

(function () {
  "use strict";

  var STORAGE_PREFIX = "solaries_guide_seen_";
  var MOBILE_BREAKPOINT = 640;
  var SIDEBAR_BREAKPOINT = 980;

  function el(tag, className, html) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (html !== undefined) node.innerHTML = html;
    return node;
  }

  function iconHelp() {
    return (
      '<svg viewBox="0 0 24 24" fill="none">' +
      '<circle cx="12" cy="12" r="9"></circle>' +
      '<path d="M9.5 9a2.5 2.5 0 1 1 3.4 2.3c-.9.4-1.4 1-1.4 2v.4"></path>' +
      '<path d="M12 17h.01"></path>' +
      "</svg>"
    );
  }

  function iconClose() {
    return (
      '<svg viewBox="0 0 24 24" fill="none">' +
      '<path d="M6 6l12 12M18 6L6 18"></path>' +
      "</svg>"
    );
  }

  function viewportHeight() {
    return window.visualViewport ? window.visualViewport.height : window.innerHeight;
  }

  function viewportWidth() {
    return window.visualViewport ? window.visualViewport.width : window.innerWidth;
  }

  function isMobile() {
    return viewportWidth() <= MOBILE_BREAKPOINT;
  }

  // An element counts as "not really visible" if it has no box, or its box
  // sits entirely off the left/right edge of the screen - which is exactly
  // how the off-canvas sidebar hides itself on narrow layouts.
  function isEffectivelyVisible(target) {
    var r = target.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    if (r.right <= 0 || r.left >= viewportWidth()) return false;
    var style = window.getComputedStyle(target);
    if (style.visibility === "hidden" || style.display === "none") return false;
    return true;
  }

  function Guide(opts) {
    this.page = opts.page || "page";
    this.steps = (opts.steps || []).filter(function (s) {
      return !s.target || document.querySelector(s.target);
    });
    this.index = 0;
    this.storageKey = STORAGE_PREFIX + this.page;
    this.open = false;
    this._sidebarOpenedByGuide = false;
    this._onReflow = this._reflow.bind(this);
    this._buildFab();
    if (this.steps.length) this._buildOverlay();
  }

  Guide.prototype.hasBeenSeen = function () {
    try {
      return localStorage.getItem(this.storageKey) === "1";
    } catch (e) {
      return false;
    }
  };

  Guide.prototype.markSeen = function () {
    try {
      localStorage.setItem(this.storageKey, "1");
    } catch (e) {}
    if (this.badge) this.badge.remove();
  };

  Guide.prototype._buildFab = function () {
    var self = this;
    var fab = el("button", "guide-fab", iconHelp());
    fab.type = "button";
    fab.setAttribute("aria-label", "Open page guide");
    fab.title = "Guide me around this page";
    if (!this.hasBeenSeen()) {
      this.badge = el("span", "guide-fab-badge");
      fab.appendChild(this.badge);
    }
    fab.addEventListener("click", function () {
      if (!self.steps.length) return;
      self.start();
    });
    document.body.appendChild(fab);
    this.fab = fab;
  };

  Guide.prototype._buildOverlay = function () {
    var self = this;
    var overlay = el("div", "guide-overlay");
    var dim = el("div", "guide-dim");
    var spot = el("div", "guide-spot");
    var card = el("div", "guide-card");

    dim.addEventListener("click", function () {
      self.stop();
    });

    overlay.appendChild(dim);
    overlay.appendChild(spot);
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    this.overlay = overlay;
    this.spot = spot;
    this.card = card;

    document.addEventListener("keydown", function (e) {
      if (!self.open) return;
      if (e.key === "Escape") self.stop();
      if (e.key === "ArrowRight") self.next();
      if (e.key === "ArrowLeft") self.prev();
    });
  };

  Guide.prototype.start = function () {
    if (!this.steps.length) return;
    this.index = 0;
    this.open = true;
    this.overlay.classList.add("is-open");
    document.body.style.overflow = "hidden";
    window.addEventListener("resize", this._onReflow);
    window.addEventListener("scroll", this._onReflow, true);
    if (window.visualViewport) {
      window.visualViewport.addEventListener("resize", this._onReflow);
    }
    this._render();
  };

  Guide.prototype.stop = function () {
    this.open = false;
    this.overlay.classList.remove("is-open");
    document.body.style.overflow = "";
    window.removeEventListener("resize", this._onReflow);
    window.removeEventListener("scroll", this._onReflow, true);
    if (window.visualViewport) {
      window.visualViewport.removeEventListener("resize", this._onReflow);
    }
    this._closeGuideSidebar();
    this.markSeen();
  };

  Guide.prototype.next = function () {
    if (this.index >= this.steps.length - 1) {
      this.stop();
      return;
    }
    this.index += 1;
    this._render();
  };

  Guide.prototype.prev = function () {
    if (this.index <= 0) return;
    this.index -= 1;
    this._render();
  };

  Guide.prototype._reflow = function () {
    if (this.open) this._render(true);
  };

  // On narrow layouts the sidebar lives off-screen until #menuToggle opens
  // it. If a step targets something inside .sidebar, open it for the
  // duration of that step and close it again once we move past it.
  Guide.prototype._ensureTargetReachable = function (targetEl) {
    if (!targetEl) return;
    if (viewportWidth() > SIDEBAR_BREAKPOINT) return;
    var insideSidebar = targetEl.closest ? targetEl.closest(".sidebar") : null;
    var menuToggle = document.getElementById("menuToggle");
    var sidebar = document.getElementById("sidebar");

    if (insideSidebar && !isEffectivelyVisible(targetEl)) {
      if (menuToggle) {
        menuToggle.click();
        this._sidebarOpenedByGuide = true;
      } else if (sidebar) {
        sidebar.classList.add("is-open");
        this._sidebarOpenedByGuide = true;
      }
      return;
    }

    if (!insideSidebar && this._sidebarOpenedByGuide) {
      this._closeGuideSidebar();
    }
  };

  Guide.prototype._closeGuideSidebar = function () {
    if (!this._sidebarOpenedByGuide) return;
    var sidebar = document.getElementById("sidebar");
    if (sidebar) sidebar.classList.remove("is-open");
    this._sidebarOpenedByGuide = false;
  };

  Guide.prototype._render = function (isReflow) {
    var step = this.steps[this.index];
    var self = this;
    var targetEl = step.target ? document.querySelector(step.target) : null;

    if (targetEl && !isReflow) {
      this._ensureTargetReachable(targetEl);
      targetEl.scrollIntoView({ block: "center", behavior: "smooth" });
    }

    // Small delay so the sidebar animation / scrollIntoView settle before
    // we measure anything.
    var delay = targetEl && !isReflow ? 260 : 0;
    setTimeout(function () {
      self._paint(step, targetEl);
    }, delay);
  };

  Guide.prototype._paint = function (step, targetEl) {
    var pad = 8;
    var visible = targetEl && isEffectivelyVisible(targetEl);

    if (visible) {
      var r = targetEl.getBoundingClientRect();
      this.spot.style.display = "block";
      this.spot.style.top = r.top - pad + "px";
      this.spot.style.left = Math.max(4, r.left - pad) + "px";
      this.spot.style.width = Math.min(r.width + pad * 2, viewportWidth() - 8) + "px";
      this.spot.style.height = r.height + pad * 2 + "px";
      this.card.classList.remove("is-centered");
    } else {
      // Target missing or still off-canvas - fall back to a centered card
      // instead of spotlighting nothing.
      this.spot.style.display = "none";
      this.card.classList.add("is-centered");
      this.card.style.top = "";
      this.card.style.left = "";
      this.card.style.bottom = "";
    }

    this._paintCardContent(step);

    if (visible) {
      this._placeCard(targetEl.getBoundingClientRect(), step.placement);
    }
  };

  Guide.prototype._placeCard = function (r, placement) {
    var vw = viewportWidth();
    var vh = viewportHeight();
    var gap = 14;
    var mobile = isMobile();

    // Measure the card after its real content is in, so width is accurate
    // instead of a guessed constant (this is what broke narrow screens).
    var cardW = this.card.offsetWidth || Math.min(300, vw - 32);
    var cardH = this.card.offsetHeight || 160;

    var side = placement || "auto";
    // On phones, left/right placement almost never fits next to a
    // sidebar-width element - always stack above or below instead.
    if (mobile && (side === "left" || side === "right")) side = "auto";

    if (side === "auto") {
      var spaceBelow = vh - r.bottom;
      var spaceAbove = r.top;
      side = spaceBelow >= cardH + gap || spaceBelow > spaceAbove ? "bottom" : "top";
    }

    var top, left;
    if (side === "bottom") {
      top = r.bottom + gap;
      left = mobile ? (vw - cardW) / 2 : r.left;
    } else if (side === "top") {
      top = null; // anchored from bottom, see below
      left = mobile ? (vw - cardW) / 2 : r.left;
    } else if (side === "right") {
      top = r.top;
      left = r.right + gap;
    } else {
      top = r.top;
      left = r.left - cardW - gap;
    }

    left = Math.max(16, Math.min(left, vw - cardW - 16));

    if (side === "top") {
      var bottomAnchor = vh - r.top + gap;
      // If anchoring from the bottom would push the card above the top
      // edge of the screen, flip to sitting below the target instead.
      if (vh - bottomAnchor - cardH < 12) {
        this.card.style.bottom = "auto";
        this.card.style.top = Math.max(12, r.bottom + gap) + "px";
      } else {
        this.card.style.top = "auto";
        this.card.style.bottom = bottomAnchor + "px";
      }
      this.card.style.left = left + "px";
      return;
    }

    top = Math.max(12, Math.min(top, vh - cardH - 12));
    this.card.style.bottom = "auto";
    this.card.style.top = top + "px";
    this.card.style.left = left + "px";
  };

  Guide.prototype._paintCardContent = function (step) {
    var self = this;
    var total = this.steps.length;
    var i = this.index;

    var dots = "";
    for (var d = 0; d < total; d++) {
      dots += '<span class="guide-dot' + (d === i ? " is-active" : "") + '"></span>';
    }

    this.card.innerHTML =
      '<div class="guide-card-eyebrow">' +
      '<span class="guide-step-pill">' + (i + 1) + " / " + total + "</span>" +
      '<button type="button" class="guide-close" aria-label="Close guide">' + iconClose() + "</button>" +
      "</div>" +
      '<h3 class="guide-card-title"></h3>' +
      '<p class="guide-card-body"></p>' +
      '<div class="guide-card-foot">' +
      '<div class="guide-dots">' + dots + "</div>" +
      '<div class="guide-actions"></div>' +
      "</div>";

    this.card.querySelector(".guide-card-title").textContent = step.title || "";
    this.card.querySelector(".guide-card-body").textContent = step.body || "";

    this.card.querySelector(".guide-close").addEventListener("click", function () {
      self.stop();
    });

    var actions = this.card.querySelector(".guide-actions");
    if (i > 0) {
      var back = el("button", "guide-btn guide-btn-ghost", "Back");
      back.type = "button";
      back.addEventListener("click", function () {
        self.prev();
      });
      actions.appendChild(back);
    }
    var next = el("button", "guide-btn guide-btn-primary", i === total - 1 ? "Done" : "Next");
    next.type = "button";
    next.addEventListener("click", function () {
      self.next();
    });
    actions.appendChild(next);
  };

  window.SolariesGuide = {
    init: function (opts) {
      return new Guide(opts);
    },
  };
})();
