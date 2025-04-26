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

// 🌐 Updated to HTTPS CyberShield domain
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const enabled = await isProtectionEnabled();
    if (!enabled) return;

    if (
      details.url.includes("cybershield.ink") // prevent looping
    ) {
      return;
    }

    console.log(`🌐 Capturing request to: ${details.url}`);

    const packet = {
      url: details.url,
      method: details.method,
      timestamp: Date.now()
    };

    fetch("https://cybershield.ink/analyze", {  // 🚀 UPDATED
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

    fetch("https://cybershield.ink/latest-alert")  // 🚀 UPDATED
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




////////////////////////////////////////////

// import { handleIncident } from "./incident_handler.js";

// console.log("🔧 CyberShield extension background script loading...");

// let lastAlertTimestamp = null;

// // ✅ Check if protection is ON
// function isProtectionEnabled() {
//   return new Promise((resolve) => {
//     chrome.storage.local.get("protectionEnabled", ({ protectionEnabled }) => {
//       resolve(protectionEnabled !== false); // default is ON
//     });
//   });
// }

// // ✅ Check if alerts are ON
// function areAlertsEnabled() {
//   return new Promise((resolve) => {
//     chrome.storage.local.get("alertsEnabled", ({ alertsEnabled }) => {
//       resolve(alertsEnabled !== false); // default is ON
//     });
//   });
// }

// // ✅ Increment stats
// function incrementPacketCount() {
//   chrome.storage.local.get("packetCount", ({ packetCount }) => {
//     chrome.storage.local.set({ packetCount: (packetCount || 0) + 1 });
//   });
// }

// function incrementThreatCount() {
//   chrome.storage.local.get("threatCount", ({ threatCount }) => {
//     chrome.storage.local.set({ threatCount: (threatCount || 0) + 1 });
//   });
// }

// // ✅ Capture outgoing requests and send to detection API
// chrome.webRequest.onBeforeRequest.addListener(
//   async (details) => {
//     const enabled = await isProtectionEnabled();
//     if (!enabled) return;

//     if (
//       details.url.includes("127.0.0.1:5002") ||
//       details.url.includes("localhost:5002") ||
//       details.url.includes("127.0.0.1:5001") ||
//       details.url.includes("localhost:5001")
//     ) {
//       return; // skip own API requests
//     }

//     console.log(`🌐 Capturing request to: ${details.url}`);

//     const packet = {
//       url: details.url,
//       method: details.method,
//       timestamp: Date.now()
//     };

//     fetch("http://127.0.0.1:5002/analyze", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify(packet)
//     })
//       .then((res) => res.json().catch(() => ({})))
//       .then((data) => {
//         console.log("🔍 Detection API response:", data);
//         incrementPacketCount();
//       })
//       .catch((err) => {
//         console.error("❌ Detection API error:", err);
//       });
//   },
//   { urls: ["<all_urls>"] },
//   ["requestBody"]
// );

// // ✅ Polling alerts every 5s, conditionally
// function checkForAlerts() {
//   isProtectionEnabled().then((enabled) => {
//     if (!enabled) {
//       console.log("🛑 Skipping alert check: protection disabled");
//       return;
//     }

//     fetch("http://127.0.0.1:5001/latest-alert")
//       .then((res) => res.json())
//       .then((alert) => {
//         if (
//           alert &&
//           alert.source === "extension" &&
//           alert.timestamp !== lastAlertTimestamp
//         ) {
//           lastAlertTimestamp = alert.timestamp;
//           console.log("🆕 New alert received");

//           // Incident response always happens
//           handleIncident(alert);

//           // Only track and alert for HIGH threats
//           if (alert.severity === "High") {
//             incrementThreatCount();

//             areAlertsEnabled().then((alertsOn) => {
//               if (alertsOn) {
//                 chrome.notifications.create({
//                   type: "basic",
//                   iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
//                   title: `🚨 High Threat Detected`,
//                   message: `A high severity threat was identified.`,
//                   priority: 2
//                 });
//               } else {
//                 console.log("🔕 Notification suppressed: alerts disabled");
//               }
//             });
//           } else {
//             console.log(`ℹ️ ${alert.severity} severity threat ignored for alert.`);
//           }
//         } else {
//           console.log("✅ No new alert to process");
//         }
//       })
//       .catch((err) => {
//         console.error("❌ Alert polling error:", err);
//       });
//   });
// }

// // ✅ Start polling loop
// setTimeout(checkForAlerts, 2000);
// setInterval(checkForAlerts, 5000);

// // ✅ Show "active" notification on load
// chrome.storage.local.get("protectionEnabled", ({ protectionEnabled }) => {
//   if (protectionEnabled !== false) {
//     chrome.notifications.create({
//       type: "basic",
//       iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
//       title: "🛡️ CyberShield Active",
//       message: "Real-time protection is now enabled",
//       priority: 0
//     });
//   }
// });

// // ✅ Message listener for toggle events
// chrome.runtime.onMessage.addListener((message) => {
//   if (message.type === "TOGGLE_PROTECTION") {
//     const isOn = message.enabled;

//     chrome.notifications.create({
//       type: "basic",
//       iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
//       title: isOn ? "🛡️ CyberShield Activated" : "🛑 CyberShield Disabled",
//       message: isOn
//         ? "Real-time protection is back on."
//         : "All monitoring and alerts have been turned off.",
//       priority: 1
//     });

//     console.log(`🔄 Extension toggled ${isOn ? "ON" : "OFF"}`);
//   }
// });

////////////////////////////////////////////////////////////



// import { handleIncident } from "./incident_handler.js";

// console.log("🔧 CyberShield extension background script loading...");

// // Track the latest alert we've processed
// let lastAlertTimestamp = null;

// /**
//  * Capture outgoing requests and send to detection API
//  */
// chrome.webRequest.onBeforeRequest.addListener(
//   (details) => {
//     // Skip if request is going to our own detection API or alert service
//     if (details.url.includes("127.0.0.1:5002") || 
//         details.url.includes("localhost:5002") ||
//         details.url.includes("127.0.0.1:5001") ||
//         details.url.includes("localhost:5001")) {
//       return; // Do nothing for our own services
//     }

//     console.log(`🌐 Capturing request to: ${details.url}`);

//     // Build a packet
//     const packet = {
//       url: details.url,
//       method: details.method,
//       timestamp: Date.now()
//     };

//     // Post to the detection API
//     fetch("http://127.0.0.1:5002/analyze", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify(packet)
//     })
//     .then(res => {
//       return res.json().catch(() => ({})); 
//     })
//     .then(data => {
//       console.log("🔍 Detection API response:", data);
//     })
//     .catch(err => {
//       console.error("❌ Detection API error:", err);
//     });
//   },
//   { urls: ["<all_urls>"] },
//   ["requestBody"]
// );

// /**
//  * Poll for alerts every 5 seconds
//  */
// function checkForAlerts() {
//   console.log("🔔 Checking for new alerts...");
  
//   fetch("http://127.0.0.1:5001/latest-alert")
//     .then(res => res.json())
//     .then(alert => {
//       console.log("📊 Latest alert:", alert);
      
//       // Check if this is a new alert from our extension
//       if (
//         alert && 
//         alert.source === "extension" && 
//         alert.timestamp !== lastAlertTimestamp
//       ) {
//         console.log("🆕 New alert detected!");
        
//         // Mark this alert as handled
//         lastAlertTimestamp = alert.timestamp;
        
//         // Process the alert
//         console.log(`⚠️ Processing ${alert.severity} severity alert`);
//         handleIncident(alert);
//       } else {
//         console.log("✅ No new alerts to process");
//       }
//     })
//     .catch(err => {
//       console.error("❌ Alert polling error:", err);
//     });
// }

// // Initial alert check
// setTimeout(checkForAlerts, 2000);

// // Set up recurring alert checks
// setInterval(checkForAlerts, 5000);

// // Extension startup notification
// chrome.notifications.create({
//   type: "basic",
//   iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
//   title: "🛡️ CyberShield Active",
//   message: "Real-time protection is now enabled",
//   priority: 0
// });

// console.log("✅ CyberShield background script loaded successfully");