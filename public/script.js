// script.js â€” Solaries multi-tenant login (Phase 0)
// The API key IS the account credential. On success, we store a
// session token that all subsequent authenticated pages use.

const form = document.getElementById("accessForm");
const apiKeyInput = document.getElementById("apiKey");
const toggleKey = document.getElementById("toggleKey");
const statusMessage = document.getElementById("statusMessage");
const submitBtn = form.querySelector(".submit-btn");

const API_BASE = "";

function showMessage(text, type) {
  statusMessage.textContent = text;
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

form.addEventListener("submit", async function (event) {
  event.preventDefault();

  const key = apiKeyInput.value.trim();
  if (!key) {
    showMessage("Please enter your API key.", "error");
    return;
  }

  submitBtn.disabled = true;
  const originalText = submitBtn.textContent;
  submitBtn.textContent = "Signing in...";

  try {
    const response = await fetch(API_BASE + "/api/signin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: key }),
    });

    const result = await response.json();

    if (result.ok) {
      // Store the session token â€” used by dashboard, projects, keys, etc.
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
    }
  } catch (error) {
    showMessage("Cannot reach the server. Try again.", "error");
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});
