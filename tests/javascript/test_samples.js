// JAVASCRIPT VULNERABLE TEST FILE

// 1. eval()
function runUserCode(userCode) {
    eval(userCode);
}

// 2. innerHTML (XSS)
function unsafeRender(input) {
    document.getElementById("output").innerHTML = input;
}

// 3. document.write() (XSS)
function writeData(data) {
    document.write(data);
}

// 4. Hardcoded API Key
const API_KEY = "AIzaSyC-pvtHardcodedKey123456";

// 5. Weak crypto (MD5)
const crypto = require("crypto");
function weakHash(data) {
    return crypto.createHash("md5").update(data).digest("hex");
}

// 6. Command injection via child_process
const { exec } = require("child_process");
function runCmd(cmd) {
    exec("ls " + cmd);
}

// 7. SQL Injection
function getUser(username) {
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    return database.query(query);
}

// 8. NoSQL Injection
function findUser(req) {
    const filter = { username: req.query.username };
    return usersCollection.find(filter); // Unsanitized input
}

// 9. Insecure JWT
const jwt = require("jsonwebtoken");
const token = jwt.sign({ admin: true }, "12345"); // Weak key

// 10. Insecure HTTP request
const http = require("http");
http.get("http://example.com/api/data", (res) => {});
