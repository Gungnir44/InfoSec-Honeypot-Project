/**
 * Attack Map Visualization
 *
 * Uses Leaflet.js to display attack origins on an interactive map
 */

let attackMap = null;
let markerGroup = null;

/**
 * Initialize the attack map
 */
async function loadAttackMap() {
    // Create map if it doesn't exist
    if (!attackMap) {
        attackMap = L.map('attack-map').setView([20, 0], 2);

        // Add tile layer (map background)
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 18,
        }).addTo(attackMap);

        // Create marker group for attack locations
        markerGroup = L.layerGroup().addTo(attackMap);
    }

    // Fetch attack map data
    try {
        const result = await fetchAPI('/attacks/map');

        if (result.success && result.data.length > 0) {
            // Clear existing markers
            markerGroup.clearLayers();

            // Add markers for each attack location
            result.data.forEach(attack => {
                // Create marker
                const marker = L.circleMarker([attack.lat, attack.lng], {
                    radius: Math.min(Math.log(attack.count) * 3, 15),
                    fillColor: getColorForCount(attack.count),
                    color: '#fff',
                    weight: 1,
                    opacity: 0.8,
                    fillOpacity: 0.6
                });

                // Add popup with attack info
                marker.bindPopup(`
                    <div style="color: #1e293b;">
                        <strong>${attack.city || attack.country || 'Unknown'}</strong><br>
                        <strong>${attack.count}</strong> attacks
                    </div>
                `);

                // Add to marker group
                marker.addTo(markerGroup);
            });

            console.log(`Added ${result.data.length} locations to map`);
        } else {
            console.log('No map data available');
        }
    } catch (error) {
        console.error('Error loading attack map:', error);
    }
}

/**
 * Get color based on attack count
 * @param {number} count - Number of attacks
 * @returns {string} - Hex color code
 */
function getColorForCount(count) {
    if (count > 100) return '#dc2626';      // Red - high
    if (count > 50) return '#f59e0b';       // Orange - medium-high
    if (count > 20) return '#fbbf24';       // Yellow - medium
    if (count > 10) return '#3b82f6';       // Blue - low-medium
    return '#10b981';                       // Green - low
}

/**
 * Update map with live data
 */
function updateMap() {
    loadAttackMap();
}

// Export for use in other scripts
window.loadAttackMap = loadAttackMap;
window.updateMap = updateMap;
