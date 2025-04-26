export function handleIncident(alert) {
  console.log("Handling incident:", alert);
  
  if (!alert || !alert.severity) {
    console.log("Invalid alert object or missing severity");
    return;
  }

  console.log(`Alert severity: ${alert.severity}`);
  
  if (alert.severity === "High") {
    console.log("🚨 HIGH SEVERITY THREAT DETECTED! Taking action...");
    
    // Extract domain from the URL
    let alertDomain = "";
    try {
      const urlObj = new URL(alert.ip);
      alertDomain = urlObj.hostname;
    } catch (e) {
      alertDomain = alert.ip;
    }
    
    // Find and close matching tabs
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (tab.url.includes(alertDomain) || tab.url.includes(alert.ip)) {
          chrome.tabs.remove(tab.id, () => {
            if (chrome.runtime.lastError) {
              console.error("❌ Error closing tab:", chrome.runtime.lastError);
            } else {
              console.log(`✅ Closed tab ${tab.id}`);
            }
          });
        }
      });
    });
    
    // 🛡️ Secure logging to CyberShield backend (updated URL)
    fetch("https://cybershield.ink/incident-log", {  // 🚀 UPDATED
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip: alert.ip,
        action: "Tab closed",
        severity: alert.severity,
        time: new Date().toISOString()
      })
    })
    .then(response => response.json())
    .then(data => console.log("📒 Incident logged:", data))
    .catch(error => console.error("❌ Error logging incident:", error));
  } else {
    console.log(`ℹ️ ${alert.severity} severity alert - no action taken`);
  }
}




// export function handleIncident(alert) {
//   console.log("Handling incident:", alert);
  
//   if (!alert || !alert.severity) {
//     console.log("Invalid alert object or missing severity");
//     return;
//   }

//   console.log(`Alert severity: ${alert.severity}`);
  
//   if (alert.severity === "High") {
//     console.log("🚨 HIGH SEVERITY THREAT DETECTED! Taking action...");
    
//     // Create notification
//     chrome.notifications.create({
//       type: "basic",
//       iconUrl: chrome.runtime.getURL("assets/logo-128.png"),
//       title: "🚨 HIGH SECURITY THREAT!",
//       message: `Blocking malicious connection to: ${alert.ip.substring(0, 50)}...`,
//       priority: 2
//     });
    
//     // Extract domain from the URL
//     let alertDomain = "";
//     try {
//       const urlObj = new URL(alert.ip);
//       alertDomain = urlObj.hostname;
//     } catch (e) {
//       // If it's not a valid URL, use the IP as is
//       alertDomain = alert.ip;
//     }
    
//     console.log(`🔍 Looking for tabs containing domain: ${alertDomain}`);
    
//     // Find and close matching tabs
//     chrome.tabs.query({}, (tabs) => {
//       console.log(`Found ${tabs.length} tabs to check`);
//       let matchFound = false;
      
//       tabs.forEach(tab => {
//         console.log(`Checking tab: ${tab.url}`);
        
//         // Check if tab URL contains the alert domain or the full alert IP
//         if (tab.url.includes(alertDomain) || tab.url.includes(alert.ip)) {
//           console.log(`🎯 MATCH FOUND! Closing tab: ${tab.id}`);
//           matchFound = true;
          
//           // Close the tab
//           chrome.tabs.remove(tab.id, () => {
//             if (chrome.runtime.lastError) {
//               console.error("❌ Error closing tab:", chrome.runtime.lastError);
//             } else {
//               console.log(`✅ Successfully closed tab ${tab.id}`);
//             }
//           });
//         }
//       });
      
//       if (!matchFound) {
//         console.log("🔎 No matching tabs found to close");
//       }
//     });
    
//     // Log the incident
//     fetch("http://localhost:5001/incident-log", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({
//         ip: alert.ip,
//         action: "Tab closed",
//         severity: alert.severity,
//         time: new Date().toISOString()
//       })
//     })
//     .then(response => response.json())
//     .then(data => console.log("📒 Incident logged:", data))
//     .catch(error => console.error("❌ Error logging incident:", error));
//   } else {
//     console.log(`ℹ️ ${alert.severity} severity alert - no action needed`);
//   }
// }