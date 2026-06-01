# SASTify - AI Security Scanner

SASTify is an AI-powered static application security testing (SAST) tool for modern JavaScript and Python applications. It deeply integrates with your editor to detect vulnerabilities instantly as you code.

## Features

- **Local-First Security Analysis**: Scans source code efficiently without sending full code to the cloud. Only vulnerable fragments are analyzed using AI.
- **Deep AI Context**: Understands complex vulnerabilities, generates high-confidence explanations, and filters out false positives.
- **Auto-Remediation**: Click **Apply Fix** to instantly refactor your code with a secure implementation.
- **Interactive Web Dashboard**: Track security trends, monitor team health scores, and export compliance reports (FERPA, HIPAA, SOC2).
- **Supports JS/TS & Python**: Optimized rules for Node.js, React, Express, FastAPI, Django, and more.

## Usage

1. Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Type `SASTify: Scan Current File` to scan the active file.
3. View the results directly in the beautiful SASTify dashboard inside VS Code!
4. Connect to your enterprise backend using `SASTify: Enter / Update API Token`.

## Enterprise Ready

To connect to your self-hosted SASTify backend or cloud instance:
1. Open settings (`Ctrl+,`).
2. Search for `SASTify`.
3. Update the `sastify.apiUrl` setting to point to your deployment.

*Protect your code effortlessly.*
