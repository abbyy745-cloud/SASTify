import * as vscode from 'vscode';
import { SASTifyProvider } from './provider';
import { ResultsPanel } from './webview/resultsPanel';

export function activate(context: vscode.ExtensionContext) {
    console.log('SASTify extension activated');

    const provider = new SASTifyProvider(context.extensionUri, context);

    // ── Core scan commands ────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('sastify.scanFile', async () => {
            await provider.scanCurrentFile();
        }),
        vscode.commands.registerCommand('sastify.scanSelection', async () => {
            await provider.scanSelection();
        }),
        vscode.commands.registerCommand('sastify.scanWorkspace', async () => {
            await provider.scanWorkspace();
        }),
        vscode.commands.registerCommand('sastify.showResults', () => {
            if (ResultsPanel.currentPanel) {
                ResultsPanel.show(context.extensionUri);
            } else {
                vscode.window.showInformationMessage('SASTify: No scan results available. Run a scan first (SASTify: Scan Current File).');
            }
        })
    );

    // ── Token management commands ─────────────────────────────────────────────
    // "Enter Token" — lets the user manually update / replace their saved token
    context.subscriptions.push(
        vscode.commands.registerCommand('sastify.enterToken', async () => {
            await provider.promptForNewToken();
        })
    );

    // "Clear Token" — wipes the saved token so the next scan re-prompts
    context.subscriptions.push(
        vscode.commands.registerCommand('sastify.clearToken', async () => {
            await provider.clearToken();
        })
    );

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

    context.subscriptions.push(
        vscode.commands.registerCommand('sastify.highlightIssues', (issues: any[]) => {
            highlightIssuesInEditor(issues, criticalDecoration, warningDecoration);
        })
    );
}

function highlightIssuesInEditor(
    issues: any[],
    criticalDecoration: vscode.TextEditorDecorationType,
    warningDecoration: vscode.TextEditorDecorationType
) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { return; }

    const criticalRanges: vscode.Range[] = [];
    const warningRanges: vscode.Range[] = [];

    (issues || []).forEach(issue => {
        const line = Math.max(0, (issue.line || 1) - 1);
        const range = new vscode.Range(line, 0, line, 1000);
        if (issue.severity === 'Critical' || issue.severity === 'High') {
            criticalRanges.push(range);
        } else {
            warningRanges.push(range);
        }
    });

    editor.setDecorations(criticalDecoration, criticalRanges);
    editor.setDecorations(warningDecoration, warningRanges);
}

export function deactivate() {
    console.log('SASTify extension deactivated');
}