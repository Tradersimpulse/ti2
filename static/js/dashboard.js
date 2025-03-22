// This file contains JavaScript for the dashboard functionality

// Update real-time dashboard data
function updateDashboardData() {
    // In a real app, this would make an API call to get current data
    // For now, we'll use dummy data

    $.ajax({
        url: '/api/dashboard-data',
        method: 'GET',
        success: function(data) {
            // Update trades count
            $('#trades-count').text(data.trades_today);

            // Update open positions
            $('#open-positions').text(data.open_positions);

            // Update daily P/L with appropriate color
            $('#daily-pl').text('$' + data.daily_pl.toFixed(2));
            if (data.daily_pl > 0) {
                $('#daily-pl').removeClass('text-danger').addClass('text-success');
            } else if (data.daily_pl < 0) {
                $('#daily-pl').removeClass('text-success').addClass('text-danger');
            }

            // Update total P/L with appropriate color
            $('#total-pl').text('$' + data.total_pl.toFixed(2));
            if (data.total_pl > 0) {
                $('#total-pl').removeClass('text-danger').addClass('text-success');
            } else if (data.total_pl < 0) {
                $('#total-pl').removeClass('text-success').addClass('text-danger');
            }
        },
        error: function() {
            console.error('Failed to fetch dashboard data');
        }
    });
}

// Document ready handler
$(document).ready(function() {
    // Initial update
    updateDashboardData();

    // Set interval for updates (every 30 seconds)
    setInterval(updateDashboardData, 30000);
});