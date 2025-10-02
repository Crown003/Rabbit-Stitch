document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');

    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            


            event.preventDefault();

           


            const usernameInput = document.getElementById('username');
            const passwordInput = document.getElementById('password');

            const username = usernameInput.value.trim();
            const password = passwordInput.value.trim();

           

            if (username === '' || password === '') {
                alert('Please enter both username and password.');
                return; 
            }

           

            console.log('Attempting to log in with:');
            console.log('Username:', username);
            console.log('Password:', password);

            

            alert(`Welcome back, ${username}!`);

            

        });
    }
});
