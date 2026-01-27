const express = require('express');
const app = express();
const openai = require('openai');

app.use(express.json());

// Vulnerability 1: PII Leakage in Logs
app.post('/register', (req, res) => {
    const student = req.body;
    console.log("Registering student:", req.body); // PII Leakage
    console.info("Params:", req.params); // PII Leakage

    // Vulnerability 2: PII Exposure in Response
    res.json(student);
});

// Vulnerability 3: Unsafe Route (No Middleware)
app.get('/student/:id', (req, res) => {
    // ... fetch student logic ...
    res.send("Student Data");
});

// Vulnerability 4: Unprotected Exam Endpoint
app.post('/api/submit_grade', (req, res) => {
    // Vulnerability 5: Submission Tampering (Trusting client)
    const score = req.body.score;
    saveGrade(score);
    res.send("Grade saved");
});

// Vulnerability 6: AI Prompt Injection
app.post('/api/ai_tutor', (req, res) => {
    const userInput = req.body.question;

    // Prompt Injection
    const prompt = "You are a helpful tutor. Answer this: " + userInput;

    openai.createCompletion({
        model: "text-davinci-003",
        prompt: prompt
    });
});

function saveGrade(score) {
    // ...
}
