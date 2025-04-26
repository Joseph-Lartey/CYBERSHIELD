document.addEventListener("DOMContentLoaded", () => {
  const protectionToggle = document.getElementById("protection-toggle");
  const statusText = document.getElementById("protection-status");
  const settingsIcon = document.querySelector(".settings-icon");
  const settingsMenu = document.getElementById("settings-menu");
  const toggleAlerts = document.getElementById("toggle-alerts");
  const exportLogs = document.getElementById("export-logs");

  const packetCountEl = document.getElementById("packet-count");
  const threatCountEl = document.getElementById("threat-count");

  // ✅ Load toggles and settings
  chrome.storage.local.get(["protectionEnabled", "alertsEnabled"], ({ protectionEnabled, alertsEnabled }) => {
    const isEnabled = protectionEnabled !== false;
    protectionToggle.checked = isEnabled;
    statusText.textContent = isEnabled ? "Active" : "Disabled";

    toggleAlerts.textContent = alertsEnabled === false ? "Enable Alerts" : "Disable Alerts";
  });

  // ✅ Load real-time stats
  chrome.storage.local.get(["packetCount", "threatCount"], ({ packetCount, threatCount }) => {
    packetCountEl.textContent = packetCount || 0;
    threatCountEl.textContent = threatCount || 0;
  });

  // ✅ Toggle extension protection
  protectionToggle.addEventListener("change", () => {
    const isEnabled = protectionToggle.checked;
    statusText.textContent = isEnabled ? "Active" : "Disabled";
    chrome.storage.local.set({ protectionEnabled: isEnabled });

    chrome.runtime.sendMessage({
      type: "TOGGLE_PROTECTION",
      enabled: isEnabled
    });
  });

  // ✅ Handle settings dropdown toggle
  settingsIcon.addEventListener("click", () => {
    settingsMenu.style.display = settingsMenu.style.display === "block" ? "none" : "block";
  });

  document.addEventListener("click", (event) => {
    const clickedInside = settingsMenu.contains(event.target) || settingsIcon.contains(event.target);
    if (!clickedInside) {
      settingsMenu.style.display = "none";
    }
  });

  // ✅ Toggle alert status
  toggleAlerts.addEventListener("click", () => {
    chrome.storage.local.get("alertsEnabled", ({ alertsEnabled }) => {
      const newState = !alertsEnabled;
      chrome.storage.local.set({ alertsEnabled: newState }, () => {
        toggleAlerts.textContent = newState ? "Disable Alerts" : "Enable Alerts";

        chrome.notifications.create({
          type: "basic",
          iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
          title: `🔔 Alerts ${newState ? "Enabled" : "Disabled"}`,
          message: `CyberShield alerts are now ${newState ? "active" : "off"}.`,
          priority: 1
        });
      });
    });
  });

  // ✅ Export logs (🛡️ UPDATED to cybershield.ink)
  exportLogs.addEventListener("click", () => {
    chrome.tabs.create({ url: "https://cybershield.ink/logs" }); // 🔥 UPDATED
  });
});
