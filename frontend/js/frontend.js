const API_URL = window.API_URL || window.location.origin;

async function register(userData) {
    try {
        const response = await fetch(`${API_URL}/register-${userData.role}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Registration failed');
        }
        alert('Registration successful!');
        window.location.href = 'email.html'; // Redirect to login page after registration

        return data; // Return data (optional based on your backend response)
    } catch (error) {
        console.error('Registration error:', error);
        throw error;
    }
}

async function login(credentials) {
    try {
        const response = await fetch(`${API_URL}/login-${credentials.role}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credentials),
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Login failed; Invalid user ID or password.');
        }
        console.log('Login successful, received data:', data);
        localStorage.setItem('token', data.token);
        localStorage.setItem('role', data.role);
        handleLoginSuccess(data); // Handle login success

        return data; // Return data (optional based on your backend response)
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    window.location.href = 'index.html';
}

function isAuthenticated() {
    return !!localStorage.getItem('token');
}

function getCurrentUserRole() {
    const role = localStorage.getItem('role');
    console.log('Current user role:', role);
    return role;
}

async function loadDashboardContent() {
    const role = getCurrentUserRole();
    if (!role) {
        console.error('Role is not defined');
        return;
    }

    const token = localStorage.getItem('token');
    const dashboardContent = document.getElementById('dashboardContent');
    if (dashboardContent) {
        try {
            console.log(`Fetching dashboard content for role: ${role}`);
            const response = await fetch(`${API_URL}/${role}-protected`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                }
            });
            if (response.status === 403) {
                // Token is invalid or expired, redirect to login page
                logout(); // Call logout function to clear local storage and update requiresOTPVerification
                throw new Error('Unauthorized');
            }
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || 'Failed to load dashboard content');
            }
            dashboardContent.innerHTML = `<h2>${role.charAt(0).toUpperCase() + role.slice(1)} Dashboard</h2>
                                          <p>Welcome to the ${role} area.</p>`;
            // Add other dashboard content based on the data
        } catch (error) {
            console.error('Dashboard content error:', error);
            alert(error.message);
        }
    }
}

// Event listeners for forms and initial page load
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userData = {
                name: document.getElementById('name').value,
                email: document.getElementById('email').value,
                password: document.getElementById('password').value,
                role: document.getElementById('role').value
            };
            try {
                await register(userData);
            } catch (error) {
                alert(error.message);
            }
        });
    }

    const loginForm = document.getElementById('loginForm');
    const otpForm = document.getElementById('otpForm');
    const resendOtpButton = document.getElementById('resendOtp');
    const countdownElement = document.getElementById('countdown');
    let countdownInterval;

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const identifier = document.getElementById('identifier').value;
            const password = document.getElementById('password').value;
            const role = document.getElementById('role').value;
    
            try {
                const res = await fetch(`${API_URL}/login-${role}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ identifier, password, role })
                });
                const data = await res.json();
    
                if (res.ok) {
                    console.log('Login response data:', data);
                    if (data.message === 'OTP required') {
                        // Save userId for OTP verification
                        localStorage.setItem('userId', data.userId);
                        localStorage.setItem('role', role); // Ensure role is saved
                        console.log("role", role);

                        // Show OTP form
                        loginForm.style.display = 'none';
                        otpForm.style.display = 'block';
                        
                        // Generate and send OTP
                        await generateAndSendOTP(data.userId);
                        
                        startCountdown(120); // Start 2-minute countdown
                    } else {
                        // Handle login success
                        handleLoginSuccess(data);
                    }
                } else {
                    // Handle HTTP errors
                    console.error('HTTP error:', res.status);
                    alert(data.message || 'Error during login');
                }
            } catch (err) {
                console.error('Login error:', err);
                alert('Error occurred during login');
            }
        });
    }

    async function generateAndSendOTP(userId) {
        try {
            const res = await fetch(`${API_URL}/generate-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId })
            });
            const data = await res.json();

            if (data.message === 'OTP sent to user') {
            } else {
                alert(data.message || 'Failed to send OTP');
            }
        } catch (err) {
            console.error('Generate OTP error:', err);
            alert('Failed to generate OTP');
        }
    }

    if (otpForm) {
        otpForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const otp = document.getElementById('otp').value;
            const userId = localStorage.getItem('userId');
            const role = localStorage.getItem('role');
            const token = localStorage.getItem('token');


    
            try {
                const res = await fetch(`${API_URL}/verify-otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId, otp, role, token})
                });
                const data = await res.json();
    
                if (data.message === 'OTP verified') {
                    localStorage.getItem('token');
                    handleLoginSuccess(data);
                } else {
                    alert(data.message || 'Invalid or expired OTP');
                }
            } catch (err) {
                console.error('OTP verification error:', err);
                alert('Error verifying OTP');
            }
        });
    }

    if (resendOtpButton) {
        resendOtpButton.addEventListener('click', async () => {
            const userId = localStorage.getItem('userId');
            await generateAndSendOTP(userId);
            startCountdown(120); // Restart 2-minute countdown for OTP
        });
    }

    function startCountdown(seconds) {
        clearInterval(countdownInterval);
        let remainingTime = seconds;

        countdownInterval = setInterval(() => {
            if (remainingTime <= 0) {
                clearInterval(countdownInterval);
                countdownElement.textContent = 'OTP expired. Please request a new one.';
                resendOtpButton.disabled = false;
            } else {
                countdownElement.textContent = `Time remaining: ${remainingTime} seconds`;
                remainingTime--;
                resendOtpButton.disabled = true;
            }
        }, 1000);
    }

    function handleLoginSuccess(data) {
        localStorage.setItem('token', data.token); // Ensure role is saved
        localStorage.setItem('role', data.role);
        console.log('Login success, redirecting to dashboard');
        alert('Login successful');
        window.location.href = 'dashboard.html'; // Redirect to dashboard on successful login
    }

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    // Check authentication for dashboard pages
    if (window.location.pathname.includes('dashboard')) {
        if (!isAuthenticated()) {
            console.log('User not authenticated, redirecting to login');
            window.location.href = 'login.html';
            alert('You need to log in.');
        } else {
            loadDashboardContent();
        }
    }
});
