import { handleIncident } from './incident_handler.js';

// Capture outgoing requests and send to detection API
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const packet = {
      url: details.url,
      method: details.method,
      timestamp: Date.now()
    };

    fetch("http://localhost:5002/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(packet)
    });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Poll for alerts every 5 seconds
setInterval(() => {
  fetch("http://localhost:5001/latest-alert")
    .then(res => res.json())
    .then(alert => {
      if (alert && alert.source === "extension") {
        handleIncident(alert);
      }
    });
}, 5000);
