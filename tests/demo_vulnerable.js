const express = require('express');
const axios = require('axios');
const app = express();

// --- 1. Universal Vulnerabilities (OWASP Top 10) ---

app.get('/users', (req, res) => {
    const userInput = req.query.name;

    // Vulnerability: SQL Injection
    const query = `SELECT * FROM users WHERE name = '${userInput}'`;
    db.execute(query);
});

function unsafeDOM(userContent) {
    // Vulnerability: Cross-Site Scripting (XSS)
    document.getElementById('app').innerHTML = userContent;
}

app.post('/fetch', (req, res) => {
    const targetUrl = req.body.url;

    // Vulnerability: SSRF
    axios.get(targetUrl);
});

function secrets() {
    // Vulnerability: Hardcoded Secret
    const awsSecret = "AKIAIOSFODNN7EXAMPLE";
}

// --- 2. EdTech Specific Vulnerabilities ---

function checkProctoring() {
    // Vulnerability: Proctoring Evasion Detection
    // Students might check this property to see if they are being watched or if the tab is hidden
    if (document.hidden) {
        console.log("Tab is hidden!");
    }
}

function logStudentData(student) {
    // Vulnerability: PII Leakage in Console
    console.log("Student Info:", student.name, student.address);
}

// --- 3. Frontend Framework Examples (Conceptual) ---

// React: <div dangerouslySetInnerHTML={{ __html: userInput }} />
// Vue: <div v-html="userInput"></div>
// Angular: <div [innerHTML]="userInput"></div>
