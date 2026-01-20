/**
 * Honeypot Dashboard - Main JavaScript
 *
 * Utility functions and shared functionality
 */

// API base URL
const API_BASE = '/api';

/**
 * Fetch data from API endpoint
 * @param {string} endpoint - API endpoint path
 * @returns {Promise} - API response data
 */
async function fetchAPI(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('API fetch error:', error);
        throw error;
    }
}

/**
 * Format timestamp to local string
 * @param {string} timestamp - ISO timestamp
 * @returns {string} - Formatted date string
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Format large numbers with commas
 * @param {number} num - Number to format
 * @returns {string} - Formatted number
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Show error message
 * @param {string} message - Error message to display
 */
function showError(message) {
    console.error(message);
    // You could also display a toast notification here
}

/**
 * Show loading state
 * @param {string} elementId - ID of element to show loading in
 */
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '<p class="loading">Loading...</p>';
    }
}

/**
 * Show no data message
 * @param {string} elementId - ID of element to show message in
 */
function showNoData(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '<p class="no-data">No data available</p>';
    }
}

/**
 * Debounce function for limiting function calls
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Chart.js default configuration
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = '#334155';
    Chart.defaults.backgroundColor = 'rgba(37, 99, 235, 0.8)';
}

// Export functions for use in other scripts
window.honeypotUtils = {
    fetchAPI,
    formatTimestamp,
    formatNumber,
    showError,
    showLoading,
    showNoData,
    debounce
};
