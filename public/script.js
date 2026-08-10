// script.js — Solaries login page (Security Hardened)
// Changes: Added Cloudflare Turnstile CAPTCHA, input validation, XSS prevention

const form = document.getElementById("accessForm");
const apiKeyInput = document.getElementById("apiKey");
const toggleKey = document.getElementById("toggleKey");
const statusMessage = document.getElementById("statusMessage");
const submitBtn = form.querySelector(".submit-btn");

const API_BASE = "";

// Escape HTML to prevent XSS in any dynamic text we display
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function showMessage(text, type) {
  statusMessage.textContent = escapeHtml(text); // textContent is already XSS-safe, but escaping for consistency
  statusMessage.className =
    "status-message is-visible " +
    (type === "success" ? "is-success" : "is-error");
}

function clearMessage() {
  statusMessage.textContent = "";
  statusMessage.className = "status-message";
}

if (toggleKey) {
  toggleKey.addEventListener("click", function () {
    const hidden = apiKeyInput.type === "password";
    apiKeyInput.type = hidden ? "text" : "password";
    toggleKey.setAttribute("aria-label", hidden ? "Hide API key" : "Show API key");
  });
}

apiKeyInput.addEventListener("input", clearMessage);

// Get Turnstile token if widget is present on the page
function getTurnstileToken() {
  if (window.turnstile) {
    return turnstile.getResponse();
  }
  return null; // Turnstile not loaded (local dev / not configured)
}

form.addEventListener("submit", async function (event) {
  event.preventDefault();

  const key = apiKeyInput.value.trim();
  if (!key) {
    showMessage("Please enter your API key.", "error");
    return;
  }

  // Client-side format check (matches server-side regex)
  if (!/^[A-Z0-9]{2,6}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(key)) {
    showMessage("Invalid key format. Example: SL-XXXX-XXXX-XXXX", "error");
    return;
  }

  // Check Turnstile if it's configured on the page
  const turnstileToken = getTurnstileToken();
  if (window.turnstile && !turnstileToken) {
    showMessage("Please complete the security check.", "error");
    return;
  }

  submitBtn.disabled = true;
  const originalText = submitBtn.textContent;
  submitBtn.textContent = "Signing in...";

  try {
    const response = await fetch(API_BASE + "/api/signin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: key, turnstile_token: turnstileToken }),
    });

    if (response.status === 429) {
      showMessage("Too many attempts. Please wait a minute and try again.", "error");
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
      if (window.turnstile) turnstile.reset();
      return;
    }

    if (response.status === 403) {
      showMessage("Security check failed. Please refresh and try again.", "error");
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
      if (window.turnstile) turnstile.reset();
      return;
    }

    const result = await response.json();

    if (result.ok) {
      sessionStorage.setItem("sl_session", result.token);
      sessionStorage.setItem("sl_account", JSON.stringify(result.account));
      showMessage("Signed in. Redirecting...", "success");
      setTimeout(function () {
        window.location.href = "dashboard.html";
      }, 500);
    } else {
      showMessage(result.error || "Invalid API key.", "error");
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
      if (window.turnstile) turnstile.reset();
    }
  } catch (error) {
    showMessage("Cannot reach the server. Try again.", "error");
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});
