const sidebar = document.getElementById("sidebar");
const menuToggle = document.getElementById("menuToggle");
const themeToggle = document.getElementById("themeToggle");
const navLinks = document.querySelectorAll(".nav-link");
const pageTitle = document.querySelector(".page-title");
const tabs = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");

/* Mobile sidebar */
if (menuToggle && sidebar) {
  menuToggle.addEventListener("click", function () {
    sidebar.classList.toggle("is-open");
  });
}

window.addEventListener("resize", function () {
  if (window.innerWidth > 980 && sidebar) {
    sidebar.classList.remove("is-open");
  }
});

/* Sidebar navigation active state */
navLinks.forEach(function (link) {
  link.addEventListener("click", function () {
    if (link.getAttribute("href") === "#signout") {
      return;
    }

    navLinks.forEach(function (item) {
      item.classList.remove("is-active");
    });
    link.classList.add("is-active");

    const label = link.querySelector("span:last-child");
    if (label && pageTitle) {
      pageTitle.textContent = label.textContent;
    }

    if (window.innerWidth <= 980 && sidebar) {
      sidebar.classList.remove("is-open");
    }
  });
});

/* Tabs */
tabs.forEach(function (tab) {
  tab.addEventListener("click", function () {
    const target = tab.getAttribute("data-tab");

    tabs.forEach(function (item) {
      item.classList.remove("is-active");
    });
    tab.classList.add("is-active");

    tabPanels.forEach(function (panel) {
      const isMatch = panel.getAttribute("data-panel") === target;
      panel.classList.toggle("is-active", isMatch);
    });
  });
});

/* Theme toggle */
if (themeToggle) {
  themeToggle.addEventListener("click", function () {
    document.body.classList.toggle("theme-light");
  });
}
