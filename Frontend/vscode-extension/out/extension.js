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
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = __importStar(require("vscode"));
const provider_1 = require("./provider");
const resultsPanel_1 = require("./webview/resultsPanel");
function activate(context) {
    console.log('SASTify extension activated');
    const provider = new provider_1.SASTifyProvider(context.extensionUri);
    // Register commands
    let scanFileCommand = vscode.commands.registerCommand('sastify.scanFile', async () => {
        await provider.scanCurrentFile();
    });
    let scanSelectionCommand = vscode.commands.registerCommand('sastify.scanSelection', async () => {
        await provider.scanSelection();
    });
    let scanWorkspaceCommand = vscode.commands.registerCommand('sastify.scanWorkspace', async () => {
        await provider.scanWorkspace();
    });
    let showResultsCommand = vscode.commands.registerCommand('sastify.showResults', () => {
        resultsPanel_1.ResultsPanel.show(context.extensionUri);
    });
    // Register text document decorator for highlighting issues
    const issueDecorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(255,0,0,0.3)',
        border: '1px solid red',
        borderRadius: '2px',
        overviewRulerColor: 'red',
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });
    const warningDecorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(255,165,0,0.3)',
        border: '1px solid orange',
        borderRadius: '2px',
        overviewRulerColor: 'orange',
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });
    context.subscriptions.push(scanFileCommand, scanSelectionCommand, scanWorkspaceCommand, showResultsCommand, issueDecorationType, warningDecorationType);
    // Store decoration types for later use
    context.subscriptions.push(vscode.commands.registerCommand('sastify.highlightIssues', (issues) => {
        highlightIssuesInEditor(issues, issueDecorationType, warningDecorationType);
    }));
}
exports.activate = activate;
function highlightIssuesInEditor(issues, criticalDecoration, warningDecoration) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return;
    }
    const criticalRanges = [];
    const warningRanges = [];
    issues.forEach(issue => {
        const line = issue.line - 1; // Convert to 0-based
        const range = new vscode.Range(line, 0, line, 1000); // Whole line
        if (issue.severity === 'Critical' || issue.severity === 'High') {
            criticalRanges.push(range);
        }
        else {
            warningRanges.push(range);
        }
    });
    editor.setDecorations(criticalDecoration, criticalRanges);
    editor.setDecorations(warningDecoration, warningRanges);
}
function deactivate() {
    console.log('SASTify extension deactivated');
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map