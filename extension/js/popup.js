// Function to show notifications
function showNotification(message) {
    const notification = document.getElementById("notification");
    notification.textContent = message;
    notification.classList.add("show");
    
    setTimeout(() => {
        notification.classList.remove("show");
    }, 3000); // Hide after 3 seconds
}

// Resolve Button Click Event
document.querySelector(".resolve-btn").addEventListener("click", function() {
    showNotification("✅ Threat Neutralized!");
});

// Activate Defense Mode Click Event
document.querySelector(".activate-btn").addEventListener("click", function() {
    showNotification("🛡️ Defense Mode Activated!");
});

// Settings Menu Toggle
document.querySelector(".settings-btn").addEventListener("click", function() {
    const menu = document.querySelector(".settings-menu");
    menu.style.display = menu.style.display === "block" ? "none" : "block";
});

// View Logs Click Event
document.getElementById("view-logs").addEventListener("click", function() {
    showNotification("📄 Opening Logs...");
});

// User Management Click Event
document.getElementById("user-management").addEventListener("click", function() {
    showNotification("👤 Opening User Management...");
});
