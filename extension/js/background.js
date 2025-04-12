import { handleIncident } from "./incident_handler.js";

/**
 * 1) Capture outgoing requests and send to detection API
 *    BUT skip requests to 127.0.0.1:5002 (our own analyze endpoint)
 *    to avoid infinite loops or self-capture.
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Skip if request is going to detection API itself
    if (details.url.includes("127.0.0.1:5002") || details.url.includes("localhost:5002")) {
      return; // Do nothing
    }

    // Otherwise, build a packet
    const packet = {
      url: details.url,
      method: details.method,
      timestamp: Date.now()
    };

    // Post to the detection API
    fetch("http://127.0.0.1:5002/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(packet)
    })
    .then(res => {
      // In case detection_api returns JSON
      return res.json().catch(() => ({})); 
    })
    .then(data => {
      console.log("Analyze API Response:", data);
    })
    .catch(err => {
      console.error("Analyze fetch error:", err);
    });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

/**
 * 2) Poll for the latest alert from the alert service every 5 seconds
 *    and handle only new, high-severity alerts from the extension.
 */
let lastAlertTimestamp = null;
setInterval(() => {
  fetch("http://127.0.0.1:5001/latest-alert")
    .then(res => res.json())
    .then(alert => {
      if (
        alert && 
        alert.source === "extension" && 
        alert.timestamp !== lastAlertTimestamp
      ) {
        // Mark this alert as handled
        lastAlertTimestamp = alert.timestamp;

        // Trigger the incident handler
        handleIncident(alert);
      }
    })
    .catch(err => console.error("Polling error:", err));
}, 5000);

console.log("🔧 background.js loaded successfully");



// import { handleIncident } from './incident_handler.js';

// // Capture outgoing requests and send to detection API
// chrome.webRequest.onBeforeRequest.addListener(
//   (details) => {
//     // 1) If the request is to localhost:5002, skip
//     if (details.url.includes("localhost:5002") || details.url.includes("127.0.0.1:5002")) {
//       return; 
//     }

//     // 2) Otherwise, proceed
//     const packet = {
//       url: details.url,
//       method: details.method,
//       timestamp: Date.now()
//     };

//     fetch("http://127.0.0.1:5002/analyze", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify(packet)
//     });
//   },
//   { urls: ["<all_urls>"] },
//   ["requestBody"]
// );

// // Poll for alerts every 5 seconds
// setInterval(() => {
//   fetch("http://http://127.0.0.1:5001/latest-alert")
//     .then(res => res.json())
//     .then(alert => {
//       if (alert && alert.source === "extension") {
//         handleIncident(alert);
//       }
//     });
// }, 5000);
