document.getElementById('loginBtn').addEventListener('click', () => {
    document.getElementById('loginModal').style.display = 'block';
});

document.getElementById('registerBtn').addEventListener('click', () => {
    document.getElementById('registerModal').style.display = 'block';
});

document.getElementById('closeLogin').onclick = () => {
    document.getElementById('loginModal').style.display = 'none';
};

document.getElementById('closeRegister').onclick = () => {
    document.getElementById('registerModal').style.display = 'none';
};

document.getElementById('closeOtp').onclick = () => {
    document.getElementById('otpModal').style.display = 'none';
};

document.getElementById('closePasswordReset').onclick = () => {
    document.getElementById('passwordResetModal').style.display = 'none';
};

document.getElementById('closeConfirmReset').onclick = () => {
    document.getElementById('confirmPasswordResetModal').style.display = 'none';
};

document.getElementById('resetPasswordLink').onclick = () => {
    document.getElementById('loginModal').style.display = 'none';
    document.getElementById('passwordResetModal').style.display = 'block';
};

// Handle registration form submission
document.getElementById('registrationForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);

    const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    document.getElementById('message').innerText = result.message || result.error;

    // If registration is successful, open OTP modal
    if (response.ok) {
        document.getElementById('registerModal').style.display = 'none';
        document.getElementById('otpModal').style.display = 'block';
        document.getElementById('otpEmail').value = data.email; // Pre-fill email in OTP modal
    }
});

// Handle OTP verification form submission
document.getElementById('otpVerificationForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);

    const response = await fetch('http://localhost:5000/verify-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    document.getElementById('message').innerText = result.message || result.error;

    if (response.ok) {
        document.getElementById('otpModal').style.display = 'none'; // Close OTP modal
    }
});

// Handle login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);

    const response = await fetch('http://localhost:5000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    document.getElementById('message').innerText = result.message || result.error;

    if (response.ok) {
        // Perform action on successful login, like redirecting or displaying user info
        console.log('Login successful:', result.user);
        document.getElementById('loginModal').style.display = 'none'; // Close login modal
    }
});

// Handle password reset request
document.getElementById('passwordResetForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);

    const response = await fetch('http://localhost:5000/request-password-reset', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    document.getElementById('message').innerText = result.message || result.error;

    if (response.ok) {
        document.getElementById('passwordResetModal').style.display = 'none';
        document.getElementById('confirmPasswordResetModal').style.display = 'block';
        document.getElementById('confirmResetEmail').value = data.email; // Pre-fill email in reset confirmation modal
    }
});

// Handle confirm password reset
document.getElementById('confirmPasswordResetForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);

    const response = await fetch('http://localhost:5000/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    document.getElementById('message').innerText = result.message || result.error;

    if (response.ok) {
        document.getElementById('confirmPasswordResetModal').style.display = 'none'; // Close confirmation modal
    }
});

// Close modals when clicking outside of them
window.onclick = function(event) {
    const modals = [document.getElementById('loginModal'), document.getElementById('registerModal'), 
                    document.getElementById('otpModal'), document.getElementById('passwordResetModal'), 
                    document.getElementById('confirmPasswordResetModal')];
    
    modals.forEach(modal => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
};
