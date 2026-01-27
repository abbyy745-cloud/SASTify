/**
 * Tricky JavaScript Test File - SASTify Stress Test
 * 
 * This file contains INTENTIONALLY VULNERABLE code for testing.
 * Mix of obvious and subtle vulnerabilities.
 */

const express = require('express');
const mysql = require('mysql');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const _ = require('lodash');

const app = express();
app.use(express.json());

// ==============================================================================
// TRICKY TEST CASE 1: SQL Injection via Template Literal
// ==============================================================================

function buildQuery(table, column, value) {
    // Looks parameterized but isn't
    return `SELECT * FROM ${table} WHERE ${column} = '${value}'`;
}

app.get('/users', (req, res) => {
    const { name } = req.query;
    const query = buildQuery('users', 'name', name);
    db.query(query, (err, results) => {  // SQL Injection!
        res.json(results);
    });
});


// ==============================================================================
// TRICKY TEST CASE 2: DOM XSS via Multiple Sinks
// ==============================================================================

function renderUserContent(content) {
    // Multiple XSS sinks
    document.getElementById('output').innerHTML = content;  // XSS!
    document.write(content);  // XSS!

    const div = document.createElement('div');
    div.innerHTML = content;  // XSS!

    // jQuery style
    $('#result').html(content);  // XSS!
}

function displayMessage() {
    const msg = new URLSearchParams(window.location.search).get('msg');
    renderUserContent(msg);  // Tainted input flows to XSS sinks
}


// ==============================================================================
// TRICKY TEST CASE 3: Command Injection with Concatenation
// ==============================================================================

function processFile(filename) {
    // Command built from user input
    const cmd = 'cat ' + filename;
    exec(cmd, (error, stdout) => {  // Command Injection!
        console.log(stdout);
    });
}

app.get('/view', (req, res) => {
    const file = req.query.file;
    processFile(file);
    res.send('Processing');
});


// ==============================================================================
// TRICKY TEST CASE 4: Hardcoded Secrets in Various Forms
// ==============================================================================

// Obvious
const API_KEY = "sk_live_1234567890abcdefghijklmnoppqrs";
const DB_PASSWORD = "SuperSecretPassword123!";

// Tricky - in object
const config = {
    database: {
        password: "my_secret_db_password_123",  // Hidden in object
        host: "localhost"
    },
    api: {
        key: "AIzaSyDOCAbC123dEf456GhI789jKL012-MnopQ"  // Google API key pattern
    }
};

// Tricky - template literal
const connectionString = `mongodb://admin:password123@localhost:27017`;

// Tricky - concatenated
const stripe_key = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx";


// ==============================================================================
// TRICKY TEST CASE 5: Prototype Pollution
// ==============================================================================

function mergeConfigs(target, source) {
    // Vulnerable to prototype pollution
    return Object.assign(target, source);  // Prototype pollution!
}

function deepMerge(target, source) {
    // Lodash merge is also vulnerable
    return _.merge(target, source);  // Prototype pollution!
}

app.post('/config', (req, res) => {
    const userConfig = req.body;
    const merged = mergeConfigs({}, userConfig);  // User controls source!
    res.json(merged);
});


// ==============================================================================
// TRICKY TEST CASE 6: eval() and Function() Usage
// ==============================================================================

function dynamicCalculator(expression) {
    // Direct eval
    return eval(expression);  // Code Injection!
}

function executeCode(code) {
    // Function constructor - same as eval
    const fn = new Function('return ' + code);  // Code Injection!
    return fn();
}

app.get('/calc', (req, res) => {
    const expr = req.query.expression;
    const result = dynamicCalculator(expr);
    res.json({ result });
});


// ==============================================================================
// TRICKY TEST CASE 7: Path Traversal
// ==============================================================================

const UPLOAD_DIR = './uploads';

function readUserFile(filename) {
    // No path validation
    const filepath = UPLOAD_DIR + '/' + filename;
    return fs.readFileSync(filepath);  // Path Traversal!
}

app.get('/download', (req, res) => {
    const file = req.query.filename;
    const content = readUserFile(file);  // ../../etc/passwd
    res.send(content);
});


// ==============================================================================
// TRICKY TEST CASE 8: Insecure Random for Security
// ==============================================================================

function generateSessionToken() {
    // Math.random is predictable
    return Math.random().toString(36).substring(2);  // Insecure!
}

function generateResetToken() {
    // Still predictable
    return Date.now().toString(36) + Math.random().toString(36);  // Insecure!
}

function generateApiKey() {
    // Using weak random for security purpose
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += Math.floor(Math.random() * 16).toString(16);  // Insecure!
    }
    return key;
}


// ==============================================================================
// TRICKY TEST CASE 9: Weak Cryptography
// ==============================================================================

function hashPassword(password) {
    // MD5 is broken
    return crypto.createHash('md5').update(password).digest('hex');  // Weak!
}

function encrypt(data, key) {
    // DES is broken
    const cipher = crypto.createCipheriv('des', key, Buffer.alloc(8));  // Weak!
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}


// ==============================================================================
// TRICKY TEST CASE 10: NoSQL Injection
// ==============================================================================

const mongoose = require('mongoose');

app.get('/find', async (req, res) => {
    const { username, password } = req.query;

    // Direct query with user input - NoSQL injection
    const user = await User.findOne({
        username: username,
        password: password  // NoSQL Injection if password = {"$gt": ""}
    });

    res.json(user);
});


// ==============================================================================
// TRICKY TEST CASE 11: SSRF
// ==============================================================================

const axios = require('axios');

async function fetchWebhook(webhookUrl) {
    // No URL validation - SSRF
    const response = await axios.get(webhookUrl);  // SSRF!
    return response.data;
}

app.get('/webhook', async (req, res) => {
    const url = req.query.url;
    const data = await fetchWebhook(url);  // http://internal-service/admin
    res.json(data);
});


// ==============================================================================
// TRICKY TEST CASE 12: Open Redirect
// ==============================================================================

app.get('/redirect', (req, res) => {
    const target = req.query.url;
    res.redirect(target);  // Open Redirect!
});

app.get('/goto', (req, res) => {
    const next = req.query.next;
    res.writeHead(302, { 'Location': next });  // Open Redirect!
    res.end();
});


// ==============================================================================
// TRICKY TEST CASE 13: RegExp DoS (ReDoS)
// ==============================================================================

function validateEmail(email) {
    // Evil regex - catastrophic backtracking
    const regex = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/;
    return regex.test(email);  // ReDoS!
}

app.get('/validate', (req, res) => {
    const email = req.query.email;
    const valid = validateEmail(email);  // aaaaaaaaaaaaaaaa@ causes freeze
    res.json({ valid });
});


// ==============================================================================
// TRICKY TEST CASE 14: Information Disclosure
// ==============================================================================

app.use((err, req, res, next) => {
    // Exposes stack trace
    console.error(err.stack);
    res.status(500).json({
        error: err.message,
        stack: err.stack,  // Information Disclosure!
        query: req.query   // Exposes request data
    });
});


// ==============================================================================
// TRICKY TEST CASE 15: JWT Weak Secret
// ==============================================================================

const jwt = require('jsonwebtoken');

const JWT_SECRET = "secret";  // Weak secret!

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET);  // Weak secret!
}

function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
}


// Start server
app.listen(3000);
