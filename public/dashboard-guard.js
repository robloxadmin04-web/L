// dashboard-guard.js
// Add this to the top of dashboard.html (before dashboard.js) to block
// direct access to the dashboard without passing the login gate first.
//
//   <script src="dashboard-guard.js"></script>
//   <script src="dashboard.js"></script>
//
// This is a convenience guard only. Real protection lives in the backend,
// which is the piece that checks the key. This just improves the flow.

(function () {
  var hasSession = sessionStorage.getItem("kf_session") === "1";
  if (!hasSession) {
    window.location.replace("index.html");
  }
})();
