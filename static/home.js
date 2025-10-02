
document.addEventListener('DOMContentLoaded', function() {
    console.log("Rabbit & Stitch website loaded!");

    






    const mobileNavToggle = document.querySelector('.mobile-nav-toggle');
    const mainNav = document.querySelector('.main-nav');
    
    if (mobileNavToggle && mainNav) {
        
        mobileNavToggle.addEventListener('click', () => {
            alert("ALERT");
            
        });
    }

});
