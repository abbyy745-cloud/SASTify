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
class SASTifyProvider {
    constructor(extensionUri) {
        this.currentScanId = null;
        const config = vscode.workspace.getConfiguration('sastify');
        // Use 127.0.0.1 to avoid IPv6 localhost issues
        this.apiUrl = config.get('apiUrl', 'http://127.0.0.1:8000');
        this.outputChannel = vscode.window.createOutputChannel('SASTify');
        this.extensionUri = extensionUri;
        this.outputChannel.appendLine(`Initialized with API URL: ${this.apiUrl}`);
    }
    async scanCurrentFile() {
        this.outputChannel.show(true);
        this.outputChannel.appendLine('Starting scan of current file...');
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor found');
            this.outputChannel.appendLine('Error: No active editor found');
            return;
        }
        const document = editor.document;
        await this.scanDocument(document, 'full');
    }
    async scanSelection() {
        this.outputChannel.show(true);
        this.outputChannel.appendLine('Starting scan of selection...');
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor found');
            return;
        }
        const selection = editor.selection;
        if (selection.isEmpty) {
            vscode.window.showErrorMessage('No code selected');
            return;
        }
        const document = editor.document;
        const selectedText = document.getText(selection);
        await this.scanCodeSnippet(selectedText, document.languageId, 'selection');
    }
    async scanWorkspace() {
        this.outputChannel.show(true);
        this.outputChannel.appendLine('Starting workspace scan...');
        const files = await vscode.workspace.findFiles('**/*.{js,ts,py}', '**/node_modules/**');
        if (files.length === 0) {
            vscode.window.showInformationMessage('No supported files found in workspace.');
            return;
        }
        this.outputChannel.appendLine(`Found ${files.length} files to scan.`);
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `SASTify: Scanning Workspace (${files.length} files)...`,
            cancellable: true
        }, async (progress, token) => {
            const startTime = Date.now();
            // Step 1: Collect all files data
            progress.report({ message: 'Collecting files...', increment: 0 });
            const filesData = [];
            for (const file of files) {
                if (token.isCancellationRequested) {
                    this.outputChannel.appendLine('Scan cancelled by user.');
                    return;
                }
                try {
                    const document = await vscode.workspace.openTextDocument(file);
                    const language = this.mapLanguageId(document.languageId);
                    if (language) {
                        filesData.push({
                            code: document.getText(),
                            language: language,
                            filename: vscode.workspace.asRelativePath(file)
                        });
                    }
                }
                catch (error) {
                    this.outputChannel.appendLine(`Error reading file ${file.fsPath}: ${error}`);
                }
            }
            if (filesData.length === 0) {
                vscode.window.showInformationMessage('No supported files found in workspace.');
                return;
            }
            // Step 2: Send batch request
            progress.report({ message: `Scanning ${filesData.length} files...`, increment: 50 });
            this.outputChannel.appendLine(`Sending batch scan request for ${filesData.length} files...`);
            try {
                const response = await axios_1.default.post(`${this.apiUrl}/api/scan-batch`, {
                    files: filesData,
                    user_id: 'vscode_user'
                }, {
                    timeout: 120000 // 2 minute timeout for batch operations
                });
                progress.report({ increment: 100 });
                const totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
                if (response.data.success) {
                    // Use the scan_id from backend response so AI analysis works
                    this.currentScanId = response.data.scan_id;
                    const result = {
                        ...response.data,
                        metrics: {
                            ...response.data.metrics,
                            scan_time: `${totalTime}s`
                        }
                    };
                    this.outputChannel.appendLine(`Workspace scan completed. Found ${result.metrics.filtered_issues} issues in ${result.metrics.files_scanned} files.`);
                    // Show results
                    if (result.issues.length > 0) {
                        this.showResults(result);
                    }
                    else {
                        vscode.window.showInformationMessage('SASTify: No security issues found in workspace.');
                    }
                }
                else {
                    const errorMsg = `Batch scan failed: ${response.data.error}`;
                    vscode.window.showErrorMessage(errorMsg);
                    this.outputChannel.appendLine(errorMsg);
                }
            }
            catch (error) {
                let errorMsg = `SASTify batch scan failed: ${error.message}`;
                if (axios_1.default.isAxiosError(error)) {
                    if (error.code === 'ECONNABORTED') {
                        errorMsg = `Connection timed out connecting to ${this.apiUrl}. Is the backend running?`;
                    }
                    else if (error.code === 'ECONNREFUSED') {
                        errorMsg = `Connection refused at ${this.apiUrl}. Is the backend running?`;
                    }
                    else if (error.response?.status === 429) {
                        errorMsg = `Rate limit exceeded. Please wait a moment and try again.`;
                    }
                }
                this.outputChannel.appendLine(errorMsg);
                vscode.window.showErrorMessage(errorMsg);
            }
        });
    }
    async scanDocument(document, scanType) {
        const code = document.getText();
        const language = this.mapLanguageId(document.languageId);
        if (!language) {
            const msg = `Unsupported language: ${document.languageId}`;
            vscode.window.showErrorMessage(msg);
            this.outputChannel.appendLine(msg);
            return;
        }
        await this.performScan(code, language, scanType, vscode.workspace.asRelativePath(document.uri));
    }
    async scanCodeSnippet(code, languageId, scanType) {
        const language = this.mapLanguageId(languageId);
        if (!language) {
            vscode.window.showErrorMessage(`Unsupported language: ${languageId}`);
            return;
        }
        await this.performScan(code, language, scanType, 'Selection');
    }
    async performScan(code, language, scanType, filename) {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `SASTify: Scanning ${scanType}...`,
            cancellable: false
        }, async (progress) => {
            progress.report({ increment: 0 });
            const result = await this.scanCodeInternal(code, language, filename);
            progress.report({ increment: 100 });
            if (result && result.success) {
                this.showResults(result);
            }
            else if (result) {
                const errorMsg = `Scan failed: ${result.error}`;
                vscode.window.showErrorMessage(errorMsg);
            }
        });
    }
    async scanCodeInternal(code, language, filename) {
        try {
            this.outputChannel.appendLine(`Scanning ${filename} (${code.length} bytes)...`);
            const scanId = `vscode_${Date.now()}_${Math.random().toString(36).substring(7)}`;
            this.currentScanId = scanId;
            const response = await axios_1.default.post(`${this.apiUrl}/api/scan`, {
                code: code,
                language: language,
                filename: filename,
                scan_id: scanId,
                user_id: 'vscode_user'
            }, {
                timeout: 10000 // 10 second timeout
            });
            if (response.data.success) {
                // Add filename to issues
                const issues = response.data.issues.map((issue) => ({
                    ...issue,
                    file: filename
                }));
                return {
                    ...response.data,
                    issues: issues
                };
            }
            else {
                return { success: false, error: response.data.error };
            }
        }
        catch (error) {
            let errorMsg = `SASTify scan failed: ${error.message}`;
            if (axios_1.default.isAxiosError(error)) {
                if (error.code === 'ECONNABORTED') {
                    errorMsg = `Connection timed out connecting to ${this.apiUrl}. Is the backend running?`;
                }
                else if (error.code === 'ECONNREFUSED') {
                    errorMsg = `Connection refused at ${this.apiUrl}. Is the backend running?`;
                }
            }
            this.outputChannel.appendLine(errorMsg);
            return { success: false, error: errorMsg };
        }
    }
    showResults(results) {
        this.outputChannel.appendLine(`Scan successful. Found ${results.metrics.filtered_issues} issues.`);
        // Highlight issues in editor
        vscode.commands.executeCommand('sastify.highlightIssues', results.issues);
        // Show results in webview
        resultsPanel_1.ResultsPanel.createOrShow(vscode.Uri.joinPath(this.extensionUri, 'media'), results, this);
        vscode.window.showInformationMessage(`SASTify found ${results.metrics.filtered_issues} security issues`, 'View Details').then(selection => {
            if (selection === 'View Details') {
                resultsPanel_1.ResultsPanel.show(this.extensionUri);
            }
        });
    }
    async analyzeIssueWithAI(issueIndex, codeSnippet) {
        if (!this.currentScanId) {
            this.currentScanId = `fallback_${Date.now()}`;
        }
        try {
            const response = await axios_1.default.post(`${this.apiUrl}/api/analyze-issue`, {
                scan_id: this.currentScanId,
                issue_index: issueIndex,
                code_snippet: codeSnippet,
                user_id: 'vscode_user'
            });
            return response.data;
        }
        catch (error) {
            throw new Error(`AI analysis failed: ${error.message}`);
        }
    }
    async reportFalsePositive(issueIndex, comment) {
        if (!this.currentScanId) {
            throw new Error('No active scan');
        }
        try {
            await axios_1.default.post(`${this.apiUrl}/api/report-false-positive`, {
                scan_id: this.currentScanId,
                issue_index: issueIndex,
                comment: comment,
                user_id: 'vscode_user'
            });
            vscode.window.showInformationMessage('False positive reported successfully');
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to report false positive: ${error.message}`);
        }
    }
    mapLanguageId(languageId) {
        const languageMap = {
            'javascript': 'javascript',
            'typescript': 'javascript',
            'python': 'python',
            'py': 'python'
        };
        return languageMap[languageId] || null;
    }
}
exports.SASTifyProvider = SASTifyProvider;
//# sourceMappingURL=provider.js.map