document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signup-form');

    if (signupForm) {
        signupForm.addEventListener('submit', function(event) {
            // Prevent the default form submission behavior
            event.preventDefault();

            // Get form data
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();

            // Simple validation
            if (username === '' || email === '' || password === '') {
                alert('Please fill out all fields.');
                return;
            }
            
            if (password.length < 8) {
                alert('Password must be at least 8 characters long.');
                return;
            }

            // --- Placeholder for actual signup logic ---
            // In a real application, you would send this data to a server
            // to create a new user account.
            console.log('Attempting to sign up with:');
            console.log('Username:', username);
            console.log('Email:', email);
            console.log('Password:', password);

            // Simulate a successful signup
            alert(`Account created for ${username}! You can now log in.`);

            // Redirect to the login page after successful signup
            window.location.href = 'login.html';
        });
    }

    // Placeholder for Google Sign-In logic
    const googleBtn = document.querySelector('.btn-google');
    if(googleBtn) {
        googleBtn.addEventListener('click', () => {
            // This is where you would trigger the Google Sign-In flow
            // using the Google Identity Services library.
            alert('Google Sign-In functionality would be implemented here.');
            console.log('Google Sign-In button clicked.');
        });
    }
});
