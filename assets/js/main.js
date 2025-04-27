function refreshAccessToken() {
    let access_token = localStorage.getItem('access_token');
    let refresh_token = localStorage.getItem('refresh_token');

    $.ajax({
        url: "/token/refresh",
        method: 'POST',
        data: { 'access_token': access_token, 'refresh_token': refresh_token },
        success: function(response) {
            console.log(response.message);
            if (response.access_token) {
                localStorage.setItem('access_token', response.access_token); // Store new token
            }
        }
    });
}

// Function to add token header to AJAX requests
function addTokenToAjaxRequest(xhr, settings) {
    if (!settings.url.includes("/token/refresh")) {
        refreshAccessToken();
        let access_token = localStorage.getItem('access_token');
        if (access_token) {
            xhr.setRequestHeader('Authorization', 'Bearer ' + access_token);
        };
    }
}


function logout() {
    let access_token = localStorage.getItem('access_token');
    let refresh_token = localStorage.getItem('refresh_token');
    let CSRFToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    $.ajax({
        url: "/logout",
        method: 'POST',
        data: { 'access_token': access_token, 'refresh_token': refresh_token },
        headers: { 'X-CSRFToken': CSRFToken },
        success: function(response) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            location.href = "/signin";
        },
        error: function(xhr, status, error) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            location.href = "/signin";
        }
    });
}

// Global AJAX setup
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        addTokenToAjaxRequest(xhr, settings);
    }
});

// Verify token expiration on page load
$(document).ready(function() {
    refreshAccessToken();
});