/**
 * Chart Visualization Functions
 *
 * Creates various charts using Chart.js
 */

let timelineChart = null;
let countriesChart = null;
let credentialsChart = null;
let commandsChart = null;

/**
 * Load timeline chart (attacks over time)
 */
async function loadTimeline() {
    try {
        const result = await fetchAPI('/attacks/timeline?days=30&interval=day');

        if (result.success && result.data.length > 0) {
            const ctx = document.getElementById('timeline-chart').getContext('2d');

            // Destroy existing chart if it exists
            if (timelineChart) {
                timelineChart.destroy();
            }

            timelineChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: result.data.map(item => new Date(item.timestamp).toLocaleDateString()),
                    datasets: [{
                        label: 'Attacks',
                        data: result.data.map(item => item.count),
                        borderColor: 'rgba(37, 99, 235, 1)',
                        backgroundColor: 'rgba(37, 99, 235, 0.2)',
                        tension: 0.3,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading timeline chart:', error);
    }
}

/**
 * Load country distribution chart
 */
async function loadCountryChart() {
    try {
        const result = await fetchAPI('/attacks/by-country');

        if (result.success && result.data.length > 0) {
            const ctx = document.getElementById('countries-chart').getContext('2d');

            // Take top 10 countries
            const topCountries = result.data.slice(0, 10);

            // Destroy existing chart
            if (countriesChart) {
                countriesChart.destroy();
            }

            countriesChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: topCountries.map(item => item.country),
                    datasets: [{
                        label: 'Attacks',
                        data: topCountries.map(item => item.count),
                        backgroundColor: 'rgba(37, 99, 235, 0.8)',
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading country chart:', error);
    }
}

/**
 * Load credentials chart
 */
async function loadCredentialsChart() {
    try {
        const result = await fetchAPI('/credentials/top?limit=10');

        if (result.success && result.data.length > 0) {
            const ctx = document.getElementById('credentials-chart').getContext('2d');

            // Destroy existing chart
            if (credentialsChart) {
                credentialsChart.destroy();
            }

            credentialsChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: result.data.map(item => `${item.username}/${item.password}`),
                    datasets: [{
                        label: 'Attempts',
                        data: result.data.map(item => item.count),
                        backgroundColor: 'rgba(220, 38, 38, 0.8)',
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading credentials chart:', error);
    }
}

/**
 * Load commands chart
 */
async function loadCommandsChart() {
    try {
        const result = await fetchAPI('/commands/top?limit=10');

        if (result.success && result.data.length > 0) {
            const ctx = document.getElementById('commands-chart').getContext('2d');

            // Destroy existing chart
            if (commandsChart) {
                commandsChart.destroy();
            }

            commandsChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: result.data.map(item => item.command.substring(0, 30)),
                    datasets: [{
                        label: 'Executions',
                        data: result.data.map(item => item.count),
                        backgroundColor: 'rgba(22, 163, 74, 0.8)',
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading commands chart:', error);
    }
}

// Export functions
window.loadTimeline = loadTimeline;
window.loadCountryChart = loadCountryChart;
window.loadCredentialsChart = loadCredentialsChart;
window.loadCommandsChart = loadCommandsChart;
