// script.js
// Login gate for index.html. Talks ONLY to the backend, never to Supabase directly.

const form = document.getElementById("accessForm");
const apiKeyInput = document.getElementById("apiKey");
const toggleKey = document.getElementById("toggleKey");
const statusMessage = document.getElementById("statusMessage");
const submitBtn = form.querySelector(".submit-btn");

// Same-origin: the site is served by the same backend, so "" works.
// If you host the front end elsewhere, set this to your Render URL.
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
    toggleKey.setAttribute(
      "aria-label",
      hidden ? "Hide API key" : "Show API key",
    );
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
  submitBtn.textContent = "Checking...";

  try {
    const response = await fetch(API_BASE + "/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: key }),
    });

    const result = await response.json();

    if (result.ok) {
      // Store a short-lived session marker so dashboard can check it.
      sessionStorage.setItem("kf_session", "1");
      showMessage("Access granted. Redirecting...", "success");
      setTimeout(function () {
        window.location.href = "dashboard.html";
      }, 600);
    } else {
      showMessage(result.error || "Invalid or revoked key.", "error");
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
    }
  } catch (error) {
    showMessage("Cannot reach the server. Try again.", "error");
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});
