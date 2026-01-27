function checkProctoring() {
    // Vulnerability: Checking if document is hidden (Proctoring Evasion)
    if (document.hidden) {
        alert("Please stay on the tab!");
    }

    // Vulnerability: Checking for WebDriver (Automation Detection Evasion)
    if (navigator.webdriver) {
        console.log("Bot detected");
    }

    // Vulnerability: Opening new window (potential cheating)
    window.open("https://google.com");
}
