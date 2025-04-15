import { handleIncident } from "./incident_handler.js";

console.log("🔧 CyberShield extension background script loading...");

// Track the latest alert we've processed
let lastAlertTimestamp = null;

/**
 * Capture outgoing requests and send to detection API
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Skip if request is going to our own detection API or alert service
    if (details.url.includes("127.0.0.1:5002") || 
        details.url.includes("localhost:5002") ||
        details.url.includes("127.0.0.1:5001") ||
        details.url.includes("localhost:5001")) {
      return; // Do nothing for our own services
    }

    console.log(`🌐 Capturing request to: ${details.url}`);

    // Build a packet
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
      return res.json().catch(() => ({})); 
    })
    .then(data => {
      console.log("🔍 Detection API response:", data);
    })
    .catch(err => {
      console.error("❌ Detection API error:", err);
    });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

/**
 * Poll for alerts every 5 seconds
 */
function checkForAlerts() {
  console.log("🔔 Checking for new alerts...");
  
  fetch("http://127.0.0.1:5001/latest-alert")
    .then(res => res.json())
    .then(alert => {
      console.log("📊 Latest alert:", alert);
      
      // Check if this is a new alert from our extension
      if (
        alert && 
        alert.source === "extension" && 
        alert.timestamp !== lastAlertTimestamp
      ) {
        console.log("🆕 New alert detected!");
        
        // Mark this alert as handled
        lastAlertTimestamp = alert.timestamp;
        
        // Process the alert
        console.log(`⚠️ Processing ${alert.severity} severity alert`);
        handleIncident(alert);
      } else {
        console.log("✅ No new alerts to process");
      }
    })
    .catch(err => {
      console.error("❌ Alert polling error:", err);
    });
}

// Initial alert check
setTimeout(checkForAlerts, 2000);

// Set up recurring alert checks
setInterval(checkForAlerts, 5000);

// Extension startup notification
chrome.notifications.create({
  type: "basic",
  iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
  title: "🛡️ CyberShield Active",
  message: "Real-time protection is now enabled",
  priority: 0
});

console.log("✅ CyberShield background script loaded successfully");