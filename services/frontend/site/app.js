/**
 * Frontend Security Dashboard Controller.
 * Security Note:
 * - All console.log statements printing JWT tokens or authentication credentials
 *   have been completely eliminated to prevent credential leakage in DevTools.
 * - JWT is stored strictly in memory for authorization headers.
 */

// Service configuration (mapped ports)
const LDAP_AUTH_URL = "http://localhost:8083";
const BACKEND_API_URL = "http://localhost:8082";

// In-memory token storage (never leaked via console.log)
let activeAuthToken = null;

// DOM Elements
const loginForm = document.getElementById("login-form");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const authStatus = document.getElementById("auth-status");
const apiStatus = document.getElementById("api-status");
const responseOutput = document.getElementById("response-output");
const btnFetchData = document.getElementById("btn-fetch-data");
const btnHealth = document.getElementById("btn-health");

function updateOutput(data, statusEl, statusText, isError = false) {
    statusEl.textContent = statusText;
    statusEl.className = `status-badge ${isError ? 'status-error' : 'status-success'}`;
    responseOutput.textContent = JSON.stringify(data, null, 2);
}

// Handle LDAP Authentication & JWT Acquisition
loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    authStatus.textContent = "Authenticating via LDAPS...";
    authStatus.className = "status-badge status-loading";
    responseOutput.textContent = "Sending credentials over secure channel...";

    try {
        const response = await fetch(`${LDAP_AUTH_URL}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                username: usernameInput.value.trim(),
                password: passwordInput.value
            })
        });

        const data = await response.json();

        if (response.ok && data.access_token) {
            // Securely store token in memory without logging it to console
            activeAuthToken = data.access_token;
            
            // Clean display: present user profile without printing raw JWT signature
            const displayProfile = {
                authenticated: true,
                user: data.user || usernameInput.value,
                token_type: data.token_type || "bearer",
                status: "Session active and token stored securely in memory."
            };
            updateOutput(displayProfile, authStatus, "Authenticated (200 OK)");
        } else {
            activeAuthToken = null;
            updateOutput(data, authStatus, `Auth Failed (${response.status})`, true);
        }
    } catch (err) {
        activeAuthToken = null;
        updateOutput({ error: err.message }, authStatus, "Network / Service Error", true);
    }
});

// Query Protected Backend
btnFetchData.addEventListener("click", async () => {
    if (!activeAuthToken) {
        updateOutput({
            warning: "No active session. Please authenticate via LDAP first."
        }, apiStatus, "Missing Token", true);
        return;
    }

    apiStatus.textContent = "Querying /api/data...";
    apiStatus.className = "status-badge status-loading";

    try {
        const response = await fetch(`${BACKEND_API_URL}/api/data`, {
            method: "GET",
            headers: {
                "Accept": "application/json",
                "Authorization": `Bearer ${activeAuthToken}`
            }
        });

        const data = await response.json();
        if (response.ok) {
            updateOutput(data, apiStatus, `${response.status} OK`);
        } else {
            updateOutput(data, apiStatus, `Error ${response.status}`, true);
        }
    } catch (err) {
        updateOutput({ error: err.message }, apiStatus, "Network Error", true);
    }
});

// Check Service Health
btnHealth.addEventListener("click", async () => {
    apiStatus.textContent = "Checking /health...";
    apiStatus.className = "status-badge status-loading";

    try {
        const response = await fetch(`${BACKEND_API_URL}/health`);
        const data = await response.json();
        updateOutput(data, apiStatus, `${response.status} OK`);
    } catch (err) {
        updateOutput({ error: err.message }, apiStatus, "Service Down", true);
    }
});
