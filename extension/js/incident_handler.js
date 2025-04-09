export function handleIncident(alert) {
    if (!alert || !alert.severity) return;
  
    if (alert.severity === "High") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "assets/logo-128.png",
        title: "🚨 High Threat Detected!",
        message: `Auto-blocking tab connected to ${alert.ip}`,
        priority: 2
      });
  
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          if (tab.url.includes(alert.ip)) {
            chrome.tabs.remove(tab.id);
          }
        });
      });
  
      fetch("http://localhost:5001/incident-log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip: alert.ip,
          action: "Tab closed",
          severity: alert.severity,
          time: new Date().toISOString()
        })
      });
    }
  }
  