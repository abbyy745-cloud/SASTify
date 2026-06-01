"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SASTifyProvider = void 0;
const vscode = __importStar(require("vscode"));
const axios_1 = __importDefault(require("axios"));
const resultsPanel_1 = require("./webview/resultsPanel");
// Key used to persist the token across VS Code sessions
const TOKEN_KEY = 'sastify.authToken';
// Timeout for AI analysis requests (30 seconds)
const AI_TIMEOUT_MS = 30000;
class SASTifyProvider {
    constructor(extensionUri, context) {
        this.currentScanId = null;
        /** Track which issue indices currently have an AI request in-flight */
        this._aiInFlight = new Set();
        const config = vscode.workspace.getConfiguration('sastify');
        this.apiUrl = config.get('apiUrl', 'http://127.0.0.1:8000');
        this.outputChannel = vscode.window.createOutputChannel('SASTify');
        this.extensionUri = extensionUri;
        this.context = context;
        this.outputChannel.appendLine(`SASTify initialised. API: ${this.apiUrl}`);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // TOKEN — stored in globalState, prompted only once per machine
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Returns the stored token. If none exists, prompts the user ONCE and
     * persists it for all future sessions. Never prompts again unless the
     * user explicitly calls `sastify.enterToken`.
     */
    async getToken() {
        // 1. Try global state first (survives VS Code restarts)
        const stored = this.context.globalState.get(TOKEN_KEY);
        if (stored && stored.trim().length > 0) {
            this.outputChannel.appendLine('🔑 Using stored token.');
            return stored;
        }
        // 2. Only prompt if no token has been saved yet
        this.outputChannel.appendLine('🔑 No token found — prompting user once…');
        const entered = await vscode.window.showInputBox({
            title: 'SASTify — Enter Your API Token',
            prompt: 'Paste the token from your SASTify dashboard. It will be saved and never asked again.',
            ignoreFocusOut: true,
            password: true,
            placeHolder: 'Paste your SASTify token here…'
        });
        if (!entered || entered.trim().length === 0) {
            vscode.window.showWarningMessage('SASTify: No token entered. Scan cancelled.');
            return undefined;
        }
        const trimmed = entered.trim();
        await this.context.globalState.update(TOKEN_KEY, trimmed);
        this.outputChannel.appendLine('✅ Token saved to global state.');
        vscode.window.showInformationMessage('SASTify: Token saved! You won\'t be asked again.');
        return trimmed;
    }
    /**
     * Allows the user to manually update / reset their token.
     * Called by the `sastify.enterToken` command.
     */
    async promptForNewToken() {
        const entered = await vscode.window.showInputBox({
            title: 'SASTify — Update API Token',
            prompt: 'Paste your new SASTify token. The old token will be replaced.',
            ignoreFocusOut: true,
            password: true,
            placeHolder: 'Paste your SASTify token here…'
        });
        if (!entered || entered.trim().length === 0) {
            vscode.window.showWarningMessage('SASTify: Token not updated.');
            return;
        }
        await this.context.globalState.update(TOKEN_KEY, entered.trim());
        vscode.window.showInformationMessage('SASTify: Token updated successfully!');
    }
    /**
     * Clears the stored token (useful for logout / token rotation).
     */
    async clearToken() {
        await this.context.globalState.update(TOKEN_KEY, undefined);
        vscode.window.showInformationMessage('SASTify: Token cleared. You will be prompted on next scan.');
    }
    /** Internal helper — builds auth headers, throws if no token available. */
    async getAuthHeaders() {
        const token = await this.getToken();
        if (!token) {
            throw new Error('No SASTify token available.');
        }
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        };
    }
    // ─────────────────────────────────────────────────────────────────────────
    // SCAN COMMANDS
    // ─────────────────────────────────────────────────────────────────────────
    async scanCurrentFile() {
        this.outputChannel.appendLine('📄 scanCurrentFile triggered');
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('SASTify: No active editor found.');
            return;
        }
        await this.scanDocument(editor.document, 'full');
    }
    async scanSelection() {
        this.outputChannel.appendLine('✂ scanSelection triggered');
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('SASTify: No active editor found.');
            return;
        }
        if (editor.selection.isEmpty) {
            vscode.window.showErrorMessage('SASTify: No code selected.');
            return;
        }
        await this.scanCodeSnippet(editor.document.getText(editor.selection), editor.document.languageId, 'selection');
    }
    async scanWorkspace() {
        this.outputChannel.appendLine('📁 scanWorkspace triggered');
        const files = await vscode.workspace.findFiles('**/*.{js,ts,py}', '**/node_modules/**');
        if (files.length === 0) {
            vscode.window.showInformationMessage('SASTify: No supported files found.');
            return;
        }
        const filesData = [];
        for (const file of files) {
            const doc = await vscode.workspace.openTextDocument(file);
            const language = this.mapLanguageId(doc.languageId);
            if (language) {
                filesData.push({
                    code: doc.getText(),
                    language,
                    filename: vscode.workspace.asRelativePath(file)
                });
            }
        }
        try {
            const headers = await this.getAuthHeaders();
            const response = await axios_1.default.post(`${this.apiUrl}/api/scan-batch`, { files: filesData }, { headers, timeout: 60000 });
            this.currentScanId = response.data.scan_id;
            this.showResults(response.data);
        }
        catch (error) {
            this.outputChannel.appendLine('❌ scanWorkspace error: ' + error.message);
            vscode.window.showErrorMessage('SASTify scan error: ' + error.message);
        }
    }
    async scanDocument(document, scanType) {
        const language = this.mapLanguageId(document.languageId);
        if (!language) {
            vscode.window.showErrorMessage('SASTify: Unsupported language: ' + document.languageId);
            return;
        }
        await this.performScan(document.getText(), language, scanType, vscode.workspace.asRelativePath(document.uri));
    }
    async scanCodeSnippet(code, languageId, scanType) {
        const language = this.mapLanguageId(languageId);
        if (!language) {
            return;
        }
        await this.performScan(code, language, scanType, 'Selection');
    }
    async performScan(code, language, scanType, filename) {
        this.outputChannel.appendLine(`⚡ performScan [${language}] ${filename}`);
        const result = await this.scanCodeInternal(code, language, filename);
        if (result && result.success) {
            this.showResults(result);
        }
    }
    async scanCodeInternal(code, language, filename) {
        try {
            this.outputChannel.appendLine('🚀 scanCodeInternal START');
            const headers = await this.getAuthHeaders();
            const response = await axios_1.default.post(`${this.apiUrl}/api/scan`, { code, language, filename }, { headers, timeout: 60000 });
            this.currentScanId = response.data.scan_id;
            this.outputChannel.appendLine('✅ scan SUCCESS');
            return response.data;
        }
        catch (error) {
            this.outputChannel.appendLine('❌ scan ERROR: ' + error.message);
            vscode.window.showErrorMessage('SASTify scan error: ' + error.message);
            return { success: false, error: error.message };
        }
    }
    // ─────────────────────────────────────────────────────────────────────────
    // RESULTS
    // ─────────────────────────────────────────────────────────────────────────
    showResults(results) {
        vscode.commands.executeCommand('sastify.highlightIssues', results.issues);
        resultsPanel_1.ResultsPanel.createOrShow(vscode.Uri.joinPath(this.extensionUri, 'media'), results, this);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // AI ANALYSIS — protected against duplicate concurrent calls
    // ─────────────────────────────────────────────────────────────────────────
    async analyzeIssueWithAI(issueIndex, codeSnippet) {
        // Guard: if a request for this issue is already in-flight, ignore
        if (this._aiInFlight.has(issueIndex)) {
            this.outputChannel.appendLine(`⏳ AI request for issue #${issueIndex} already in-flight — skipping.`);
            throw new Error('AI analysis already in progress for this issue. Please wait.');
        }
        this._aiInFlight.add(issueIndex);
        this.outputChannel.appendLine(`🤖 AI analysis START — issue #${issueIndex}`);
        try {
            const headers = await this.getAuthHeaders();
            const response = await axios_1.default.post(`${this.apiUrl}/api/analyze-issue`, {
                scan_id: this.currentScanId,
                issue_index: issueIndex,
                code_snippet: codeSnippet
            }, { headers, timeout: AI_TIMEOUT_MS });
            this.outputChannel.appendLine(`✅ AI analysis DONE — issue #${issueIndex}`);
            return response.data;
        }
        catch (error) {
            const isTimeout = error.code === 'ECONNABORTED' || error.message?.includes('timeout');
            const msg = isTimeout
                ? 'AI analysis timed out. The model may be busy — please try again shortly.'
                : error.message;
            this.outputChannel.appendLine(`❌ AI analysis ERROR — issue #${issueIndex}: ${msg}`);
            throw new Error(msg);
        }
        finally {
            // Always clear the in-flight flag so the user can retry
            this._aiInFlight.delete(issueIndex);
        }
    }
    // ─────────────────────────────────────────────────────────────────────────
    // FALSE POSITIVE
    // ─────────────────────────────────────────────────────────────────────────
    async reportFalsePositive(issueIndex, comment) {
        try {
            const headers = await this.getAuthHeaders();
            await axios_1.default.post(`${this.apiUrl}/api/report-false-positive`, { scan_id: this.currentScanId, issue_index: issueIndex, comment }, { headers, timeout: 15000 });
            vscode.window.showInformationMessage('SASTify: False positive reported — thank you!');
        }
        catch (error) {
            this.outputChannel.appendLine('❌ reportFalsePositive error: ' + error.message);
            vscode.window.showErrorMessage('SASTify: Could not report false positive: ' + error.message);
        }
    }
    // ─────────────────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────────────────
    mapLanguageId(languageId) {
        const map = {
            javascript: 'javascript',
            typescript: 'javascript',
            python: 'python',
            java: 'java',
            kotlin: 'kotlin',
            swift: 'swift',
            dart: 'dart',
            php: 'php'
        };
        return map[languageId] ?? null;
    }
}
exports.SASTifyProvider = SASTifyProvider;
//# sourceMappingURL=provider.js.map