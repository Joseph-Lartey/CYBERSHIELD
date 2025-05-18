import { handleIncident } from "./incident_handler.js";

console.log("🔧 CyberShield extension background script loading...");

let lastAlertTimestamp = null;

function isProtectionEnabled() {
  return new Promise((resolve) => {
    chrome.storage.local.get("protectionEnabled", ({ protectionEnabled }) => {
      resolve(protectionEnabled !== false);
    });
  });
}

function areAlertsEnabled() {
  return new Promise((resolve) => {
    chrome.storage.local.get("alertsEnabled", ({ alertsEnabled }) => {
      resolve(alertsEnabled !== false);
    });
  });
}

function incrementPacketCount() {
  chrome.storage.local.get("packetCount", ({ packetCount }) => {
    chrome.storage.local.set({ packetCount: (packetCount || 0) + 1 });
  });
}

function incrementThreatCount() {
  chrome.storage.local.get("threatCount", ({ threatCount }) => {
    chrome.storage.local.set({ threatCount: (threatCount || 0) + 1 });
  });
}

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const enabled = await isProtectionEnabled();
    if (!enabled) return;

    if (
      details.url.includes("cybershield.ink") // prevent looping
    ) {
      return;
    }

    console.log(`Capturing request to: ${details.url}`);

    const packet = {
      url: details.url,
      method: details.method,
      timestamp: Date.now()
    };

    fetch("https://cybershield.ink/analyze", {  
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(packet)
    })
      .then((res) => res.json().catch(() => ({})))
      .then((data) => {
        console.log("🔍 Detection API response:", data);
        incrementPacketCount();
      })
      .catch((err) => {
        console.error("❌ Detection API error:", err);
      });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// 🚨 Check for alerts securely
function checkForAlerts() {
  isProtectionEnabled().then((enabled) => {
    if (!enabled) {
      console.log("🛑 Skipping alert check: protection disabled");
      return;
    }

    fetch("https://cybershield.ink/latest-alert")  
      .then((res) => res.json())
      .then((alert) => {
        if (
          alert &&
          alert.source === "extension" &&
          alert.timestamp !== lastAlertTimestamp
        ) {
          lastAlertTimestamp = alert.timestamp;
          console.log("🆕 New alert received");

          handleIncident(alert);

          if (alert.severity === "High") {
            incrementThreatCount();

            areAlertsEnabled().then((alertsOn) => {
              if (alertsOn) {
                chrome.notifications.create({
                  type: "basic",
                  iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
                  title: `🚨 High Threat Detected`,
                  message: `A high severity threat was identified.`,
                  priority: 2
                });
              } else {
                console.log("🔕 Notification suppressed: alerts disabled");
              }
            });
          } else {
            console.log(`ℹ️ ${alert.severity} severity threat ignored for alert.`);
          }
        } else {
          console.log("✅ No new alert to process");
        }
      })
      .catch((err) => {
        console.error("❌ Alert polling error:", err);
      });
  });
}

setTimeout(checkForAlerts, 2000);
setInterval(checkForAlerts, 5000);

chrome.storage.local.get("protectionEnabled", ({ protectionEnabled }) => {
  if (protectionEnabled !== false) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
      title: "🛡️ CyberShield Active",
      message: "Real-time protection is now enabled",
      priority: 0
    });
  }
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "TOGGLE_PROTECTION") {
    const isOn = message.enabled;

    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
      title: isOn ? "🛡️ CyberShield Activated" : "🛑 CyberShield Disabled",
      message: isOn
        ? "Real-time protection is back on."
        : "All monitoring and alerts have been turned off.",
      priority: 1
    });

    console.log(`🔄 Extension toggled ${isOn ? "ON" : "OFF"}`);
  }
});

