const form = document.getElementById("accessForm");
const apiKeyInput = document.getElementById("apiKey");
const toggleKeyButton = document.getElementById("toggleKey");
const statusMessage = document.getElementById("statusMessage");

const allowedKeys = ["demo-key-001", "owner-access-002", "client-access-003"];

function showMessage(message, type) {
  statusMessage.textContent = message;
  statusMessage.className = "status-message is-visible";

  if (type === "success") {
    statusMessage.classList.add("is-success");
  } else {
    statusMessage.classList.add("is-error");
  }
}

function clearMessage() {
  statusMessage.textContent = "";
  statusMessage.className = "status-message";
}

toggleKeyButton.addEventListener("click", function () {
  const isHidden = apiKeyInput.type === "password";
  apiKeyInput.type = isHidden ? "text" : "password";
  toggleKeyButton.setAttribute(
    "aria-label",
    isHidden ? "Hide API key" : "Show API key",
  );
});

apiKeyInput.addEventListener("input", function () {
  clearMessage();
});

form.addEventListener("submit", function (event) {
  event.preventDefault();

  const enteredKey = apiKeyInput.value.trim();

  if (!enteredKey) {
    showMessage("Please enter your API key.", "error");
    return;
  }

  if (!allowedKeys.includes(enteredKey)) {
    showMessage("Invalid API key. Please contact the owner.", "error");
    return;
  }

  showMessage("Access granted. Redirecting...", "success");

  setTimeout(function () {
    window.location.href = "dashboard.html";
  }, 800);
});
