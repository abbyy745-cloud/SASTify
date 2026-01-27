import * as vscode from 'vscode';
import { SASTifyProvider } from './provider';
import { ResultsPanel } from './webview/resultsPanel';

export function activate(context: vscode.ExtensionContext) {
    console.log('SASTify extension activated');

    const provider = new SASTifyProvider(context.extensionUri);

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
        ResultsPanel.show(context.extensionUri);
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

    context.subscriptions.push(
        scanFileCommand,
        scanSelectionCommand,
        scanWorkspaceCommand,
        showResultsCommand,
        issueDecorationType,
        warningDecorationType
    );

    // Store decoration types for later use
    context.subscriptions.push(
        vscode.commands.registerCommand('sastify.highlightIssues', (issues: any[]) => {
            highlightIssuesInEditor(issues, issueDecorationType, warningDecorationType);
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

    issues.forEach(issue => {
        const line = issue.line - 1; // Convert to 0-based
        const range = new vscode.Range(line, 0, line, 1000); // Whole line

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