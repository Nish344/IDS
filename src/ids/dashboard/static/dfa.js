// src/ids/dashboard/static/dfa.js

// Global references
let panZoomInstance = null;
let viz = new Viz();
let currentDotData = null; // Store data for reuse in downloads

document.addEventListener("DOMContentLoaded", () => {
    // Bind buttons
    const btnRefresh = document.getElementById("btn-refresh");
    if (btnRefresh) btnRefresh.addEventListener("click", loadGraph);

    const btnDownload = document.getElementById("btn-download");
    if (btnDownload) btnDownload.addEventListener("click", downloadDot);

    const btnDownloadImg = document.getElementById("btn-download-img");
    if (btnDownloadImg) btnDownloadImg.addEventListener("click", downloadImage);

    // Initial load
    loadGraph();
});

function loadGraph() {
    const container = document.getElementById("viz-container");
    
    // Reset container and UI
    if (panZoomInstance) {
        if (typeof panZoomInstance.destroy === 'function') {
            panZoomInstance.destroy();
        }
        panZoomInstance = null;
    }
    container.innerHTML = '<div class="loading">Fetching DFA structure...</div>';

    fetch("/api/dfa/dot")
        .then(response => {
            if (!response.ok) throw new Error("Failed to load DOT data");
            return response.text();
        })
        .then(dotData => {
            currentDotData = dotData; // Store for export
            container.innerHTML = '<div class="loading">Rendering graph...</div>';
            
            // Render DOT to SVG Element using Viz.js
            return viz.renderSVGElement(dotData);
        })
        .then(element => {
            container.innerHTML = ""; // Clear loading message
            
            // Append the SVG to the container
            element.setAttribute("width", "100%");
            element.setAttribute("height", "100%");
            container.appendChild(element);

            // Enable Pan/Zoom with safety check
            if (typeof svgPanZoom !== 'undefined') {
                try {
                    panZoomInstance = svgPanZoom(element, {
                        zoomEnabled: true,
                        controlIconsEnabled: true,
                        fit: true,
                        center: true,
                        minZoom: 0.1,
                        maxZoom: 10
                    });
                    console.log("✓ Graph rendered with Zoom enabled.");
                } catch (e) {
                    console.warn("Zoom initialization failed:", e);
                }
            } else {
                console.warn("svg-pan-zoom library not loaded. Graph will be static.");
                container.style.overflow = "auto";
            }
        })
        .catch(err => {
            console.error("Graph Error:", err);
            
            let msg = err.message || err;
            if (msg.toString().includes("syntax error")) {
                msg = "DOT Syntax Error (The graph definition is invalid)";
            }
            
            container.innerHTML = `<div style="color:red; padding:20px; text-align:center;">
                <h3>Rendering Failed</h3>
                <p>${msg}</p>
                <small>Check browser console for details.</small>
            </div>`;
        });
}

function downloadDot() {
    window.open("/api/dfa/dot", "_blank");
}

function downloadImage() {
    if (!currentDotData) {
        alert("Graph data not loaded yet.");
        return;
    }

    const btn = document.getElementById("btn-download-img");
    const originalText = btn.textContent;
    btn.textContent = "Generating...";
    btn.disabled = true;

    // Use Viz.js to render a PNG image directly
    // Scale: 2 ensures high resolution (Retina-like quality)
    viz.renderImageElement(currentDotData, { scale: 2, mimeType: "image/png" })
        .then(image => {
            // Create a virtual link to trigger download
            const link = document.createElement("a");
            link.href = image.src; // Data URL
            link.download = "ids_dfa_automaton.png";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            // Reset button
            btn.textContent = originalText;
            btn.disabled = false;
        })
        .catch(err => {
            console.error("Image Export Error:", err);
            alert("Failed to generate image. Try downloading DOT file instead.");
            btn.textContent = originalText;
            btn.disabled = false;
        });
}