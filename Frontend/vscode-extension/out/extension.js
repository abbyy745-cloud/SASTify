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
    const provider = new provider_1.SASTifyProvider(context.extensionUri, context);
    // ── Core scan commands ────────────────────────────────────────────────────
    context.subscriptions.push(vscode.commands.registerCommand('sastify.scanFile', async () => {
        await provider.scanCurrentFile();
    }), vscode.commands.registerCommand('sastify.scanSelection', async () => {
        await provider.scanSelection();
    }), vscode.commands.registerCommand('sastify.scanWorkspace', async () => {
        await provider.scanWorkspace();
    }), vscode.commands.registerCommand('sastify.showResults', () => {
        resultsPanel_1.ResultsPanel.show(context.extensionUri);
    }));
    // ── Token management commands ─────────────────────────────────────────────
    // "Enter Token" — lets the user manually update / replace their saved token
    context.subscriptions.push(vscode.commands.registerCommand('sastify.enterToken', async () => {
        await provider.promptForNewToken();
    }));
    // "Clear Token" — wipes the saved token so the next scan re-prompts
    context.subscriptions.push(vscode.commands.registerCommand('sastify.clearToken', async () => {
        await provider.clearToken();
    }));
    // ── Decoration types for in-editor highlighting ───────────────────────────
    const criticalDecoration = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(239,68,68,0.25)',
        border: '1px solid rgba(239,68,68,0.6)',
        borderRadius: '2px',
        overviewRulerColor: '#ef4444',
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });
    const warningDecoration = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(249,115,22,0.2)',
        border: '1px solid rgba(249,115,22,0.5)',
        borderRadius: '2px',
        overviewRulerColor: '#f97316',
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });
    context.subscriptions.push(criticalDecoration, warningDecoration);
    context.subscriptions.push(vscode.commands.registerCommand('sastify.highlightIssues', (issues) => {
        highlightIssuesInEditor(issues, criticalDecoration, warningDecoration);
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
    (issues || []).forEach(issue => {
        const line = Math.max(0, (issue.line || 1) - 1);
        const range = new vscode.Range(line, 0, line, 1000);
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