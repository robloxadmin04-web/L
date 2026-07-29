const STORAGE_KEY = "kf_api_keys";
const form = document.getElementById("accessForm");
const apiKeyInput = document.getElementById("apiKey");
const toggleKey = document.getElementById("toggleKey");
const statusMessage = document.getElementById("statusMessage");

function loadKeys() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (error) {
    return [];
  }
}

function showMessage(text, type) {
  statusMessage.textContent = text;
  statusMessage.className =
    "status-message is-visible " +
    (type === "success" ? "is-success" : "is-error");
}

toggleKey.addEventListener("click", function () {
  const hidden = apiKeyInput.type === "password";
  apiKeyInput.type = hidden ? "text" : "password";
});

form.addEventListener("submit", function (event) {
  event.preventDefault();
  const entered = apiKeyInput.value.trim();

  if (!entered) {
    showMessage("Please enter your API key.", "error");
    return;
  }

  const match = loadKeys().find(function (item) {
    return item.key === entered && !item.revoked;
  });

  if (!match) {
    showMessage("Invalid or revoked key. Contact the owner.", "error");
    return;
  }

  showMessage("Access granted. Redirecting...", "success");
  setTimeout(function () {
    window.location.href = "dashboard.html";
  }, 700);
});
