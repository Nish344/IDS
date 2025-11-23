console.log("dashboard.js loaded");

const socket = io("http://127.0.0.1:5000", {
    transports: ["websocket", "polling"],
    upgrade: true,
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: 5
});

let alertCount = 0;

socket.on("connect", () => {
    console.log("✓ Connected to socket server");
    console.log("Socket ID:", socket.id);
    console.log("Transport:", socket.io.engine.transport.name);
    
    // Show connection status on page
    updateConnectionStatus(true);
});

socket.on("disconnect", (reason) => {
    console.log("✗ Disconnected from socket server. Reason:", reason);
    updateConnectionStatus(false);
});

socket.on("connect_error", (error) => {
    console.error("Connection error:", error);
    updateConnectionStatus(false);
});

socket.on("new_alert", (alert) => {
    alertCount++;
    console.log(`✓ Received alert #${alertCount}:`, alert);
    
    const container = document.getElementById("alerts");
    const div = document.createElement("div");
    div.className = "alert-box";
    div.innerHTML = `
        <b>SID ${alert.sid}: ${alert.msg}</b><br>
        Pattern: <code>${alert.pattern}</code><br>
        Flow: ${alert.src} → ${alert.dst}<br>
        Direction: ${alert.direction}<br>
        <span class="time">${new Date().toLocaleTimeString()}</span>
    `;
    container.prepend(div);
    
    // Add animation
    div.style.animation = "slideIn 0.3s ease-out";
    
    // Update alert counter
    updateAlertCount();
});

function updateConnectionStatus(connected) {
    let statusDiv = document.getElementById("connection-status");
    if (!statusDiv) {
        statusDiv = document.createElement("div");
        statusDiv.id = "connection-status";
        statusDiv.style.cssText = "padding: 10px; margin-bottom: 20px; border-radius: 5px; font-weight: bold;";
        document.body.insertBefore(statusDiv, document.getElementById("alerts"));
    }
    
    if (connected) {
        statusDiv.style.background = "#d4edda";
        statusDiv.style.color = "#155724";
        statusDiv.textContent = `✓ Connected to IDS Server (ID: ${socket.id})`;
    } else {
        statusDiv.style.background = "#f8d7da";
        statusDiv.style.color = "#721c24";
        statusDiv.textContent = "✗ Disconnected from IDS Server";
    }
}

function updateAlertCount() {
    let countDiv = document.getElementById("alert-count");
    if (!countDiv) {
        countDiv = document.createElement("div");
        countDiv.id = "alert-count";
        countDiv.style.cssText = "padding: 10px; margin-bottom: 10px; background: #fff3cd; color: #856404; border-radius: 5px;";
        const alertsDiv = document.getElementById("alerts");
        alertsDiv.parentNode.insertBefore(countDiv, alertsDiv);
    }
    countDiv.textContent = `Total Alerts Received: ${alertCount}`;
}

// Test button and debug info
document.addEventListener("DOMContentLoaded", () => {
    const debugDiv = document.createElement("div");
    debugDiv.style.cssText = "margin-bottom: 20px; padding: 10px; background: #e7f3ff; border-radius: 5px;";
    
    const testBtn = document.createElement("button");
    testBtn.textContent = "🔍 Debug Socket Connection";
    testBtn.style.cssText = "padding: 10px 20px; cursor: pointer; margin-right: 10px; background: #007bff; color: white; border: none; border-radius: 5px;";
    testBtn.onclick = () => {
        console.log("=== Socket Debug Info ===");
        console.log("Connected:", socket.connected);
        console.log("Socket ID:", socket.id);
        console.log("Transport:", socket.io.engine.transport.name);
        console.log("Alerts received:", alertCount);
        alert(`Socket Connected: ${socket.connected}\nSocket ID: ${socket.id}\nAlerts Received: ${alertCount}`);
    };
    
    const clearBtn = document.createElement("button");
    clearBtn.textContent = "🗑️ Clear Alerts";
    clearBtn.style.cssText = "padding: 10px 20px; cursor: pointer; background: #dc3545; color: white; border: none; border-radius: 5px;";
    clearBtn.onclick = () => {
        document.getElementById("alerts").innerHTML = "";
        alertCount = 0;
        updateAlertCount();
    };
    
    debugDiv.appendChild(testBtn);
    debugDiv.appendChild(clearBtn);
    document.body.insertBefore(debugDiv, document.getElementById("alerts"));
});

// Add CSS animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
`;
document.head.appendChild(style);