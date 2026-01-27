import * as vscode from 'vscode';
import * as path from 'path';
import { SASTifyProvider } from '../provider';

export class ResultsPanel {
    public static currentPanel: ResultsPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private readonly _provider: SASTifyProvider;
    private _disposables: vscode.Disposable[] = [];
    private _scanResults: any;
    private _scanHistory: any[] = [];

    public static show(extensionUri: vscode.Uri, scanResults?: any, provider?: SASTifyProvider): void {
        if (scanResults && provider) {
            ResultsPanel.createOrShow(extensionUri, scanResults, provider);
        } else if (ResultsPanel.currentPanel) {
            ResultsPanel.currentPanel._panel.reveal(vscode.ViewColumn.Two);
        }
    }

    public static createOrShow(extensionUri: vscode.Uri, scanResults: any, provider: SASTifyProvider): void {
        const column = vscode.ViewColumn.Two;
        if (ResultsPanel.currentPanel) {
            ResultsPanel.currentPanel._panel.reveal(column);
            ResultsPanel.currentPanel._update(scanResults);
            return;
        }
        const panel = vscode.window.createWebviewPanel(
            'sastifyResults',
            'SASTify Security Results',
            column,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [extensionUri]
            }
        );
        ResultsPanel.currentPanel = new ResultsPanel(panel, extensionUri, scanResults, provider);
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, scanResults: any, provider: SASTifyProvider) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._provider = provider;
        this._scanResults = scanResults;
        this._update(scanResults);

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._panel.webview.onDidReceiveMessage(async (message: any) => {
            switch (message.command) {
                case 'analyzeWithAI':
                    await this.handleAIAnalysis(message.issueIndex, message.codeSnippet);
                    break;
                case 'reportFalsePositive':
                    await this.handleFalsePositiveReport(message.issueIndex, message.comment);
                    break;
                case 'applyFix':
                    await this.applyFixToEditor(message.fix, message.explanation, message.issueIndex);
                    break;
                case 'exportResults':
                    await this.exportAllResults(message.format);
                    break;
                case 'goToLine':
                    await this.goToLine(message.file, message.line);
                    break;
                case 'filterIssues':
                    this.filterIssues(message.filter);
                    break;
            }
        }, null, this._disposables);
    }

    private async goToLine(file: string, line: number): Promise<void> {
        try {
            let fileUri: vscode.Uri | undefined;
            if (file && path.isAbsolute(file)) {
                fileUri = vscode.Uri.file(file);
            } else if (file) {
                const files = await vscode.workspace.findFiles(`**/${file}`);
                if (files.length > 0) {
                    fileUri = files[0];
                }
            }

            if (fileUri) {
                const document = await vscode.workspace.openTextDocument(fileUri);
                const editor = await vscode.window.showTextDocument(document, {
                    viewColumn: vscode.ViewColumn.One,
                    preserveFocus: false
                });

                const position = new vscode.Position(Math.max(0, line - 1), 0);
                editor.selection = new vscode.Selection(position, position);
                editor.revealRange(
                    new vscode.Range(position, position),
                    vscode.TextEditorRevealType.InCenter
                );
            }
        } catch (error: any) {
            vscode.window.showErrorMessage(`Could not navigate to file: ${error.message}`);
        }
    }

    private filterIssues(filter: any): void {
        // Re-render with filter applied
        this._update(this._scanResults, filter);
    }

    private async handleAIAnalysis(issueIndex: number, codeSnippet: string): Promise<void> {
        try {
            const result = await this._provider.analyzeIssueWithAI(issueIndex, codeSnippet);
            this._panel.webview.postMessage({
                command: 'aiAnalysisResult',
                issueIndex: issueIndex,
                analysis: result.ai_analysis
            });
        } catch (error: any) {
            this._panel.webview.postMessage({
                command: 'aiAnalysisError',
                issueIndex: issueIndex,
                error: error.message
            });
        }
    }

    private async handleFalsePositiveReport(issueIndex: number, comment: string): Promise<void> {
        await this._provider.reportFalsePositive(issueIndex, comment);
        this._panel.webview.postMessage({
            command: 'falsePositiveReported',
            issueIndex: issueIndex
        });
        vscode.window.showInformationMessage('False positive reported. Thanks for helping improve SASTify!');
    }

    private async exportAllResults(format: string): Promise<void> {
        const allIssues = this._scanResults.allIssues || this._scanResults.issues || [];
        const ts = new Date().toISOString().replace(/[:.]/g, '-');

        if (format === 'json') {
            const content = JSON.stringify({
                exportDate: new Date().toISOString(),
                tool: 'SASTify v1.0.0',
                totalIssues: allIssues.length,
                metrics: this._scanResults.metrics,
                issues: allIssues
            }, null, 2);

            const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`sastify-results-${ts}.json`),
                filters: { 'JSON': ['json'] }
            });

            if (uri) {
                await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
                vscode.window.showInformationMessage(`Exported ${allIssues.length} issues to JSON`);
            }
        } else if (format === 'sarif') {
            // SARIF format for GitHub Security
            const sarif = this.generateSarifReport(allIssues);
            const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`sastify-results-${ts}.sarif`),
                filters: { 'SARIF': ['sarif', 'json'] }
            });

            if (uri) {
                await vscode.workspace.fs.writeFile(uri, Buffer.from(JSON.stringify(sarif, null, 2), 'utf8'));
                vscode.window.showInformationMessage(`Exported ${allIssues.length} issues to SARIF`);
            }
        } else {
            const html = this.generatePremiumHtmlReport(allIssues);
            const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`sastify-report-${ts}.html`),
                filters: { 'HTML': ['html'] }
            });

            if (uri) {
                await vscode.workspace.fs.writeFile(uri, Buffer.from(html, 'utf8'));
                vscode.window.showInformationMessage(`Exported ${allIssues.length} issues to HTML report`);
            }
        }
    }

    private generateSarifReport(issues: any[]): any {
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SASTify",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourusername/sastify"
                    }
                },
                "results": issues.map((issue, idx) => ({
                    "ruleId": `SAST-${String(idx).padStart(3, '0')}`,
                    "level": issue.severity === 'Critical' || issue.severity === 'High' ? 'error' : 'warning',
                    "message": { "text": issue.description || issue.type },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": issue.file || 'unknown' },
                            "region": { "startLine": issue.line || 1 }
                        }
                    }]
                }))
            }]
        };
    }

    private generatePremiumHtmlReport(issues: any[]): string {
        const sc: any = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        for (const i of issues) {
            if (sc[i.severity] !== undefined) { sc[i.severity]++; }
        }

        const totalRisk = sc.Critical * 10 + sc.High * 5 + sc.Medium * 2 + sc.Low * 1;
        const riskLevel = totalRisk > 50 ? 'Critical' : totalRisk > 20 ? 'High' : totalRisk > 5 ? 'Medium' : 'Low';

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SASTify Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%);
            color: #e8e8e8;
            min-height: 100vh;
            padding: 40px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.03);
            border-radius: 24px;
            border: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
            backdrop-filter: blur(20px);
        }
        .logo {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(90deg, #00d4ff, #7b2ff7, #f222ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .subtitle { color: #888; font-size: 1.1rem; }
        .risk-score {
            display: inline-block;
            padding: 15px 40px;
            border-radius: 999px;
            font-weight: 600;
            font-size: 1.2rem;
            margin-top: 20px;
        }
        .risk-score.critical { background: linear-gradient(90deg, #ff4757, #ff6b81); }
        .risk-score.high { background: linear-gradient(90deg, #ff6b6b, #ff8e8e); }
        .risk-score.medium { background: linear-gradient(90deg, #ffa502, #ffbe76); color: #000; }
        .risk-score.low { background: linear-gradient(90deg, #20c997, #4dd4ac); }
        .stats {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.08);
            transition: all 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); border-color: rgba(255,255,255,0.2); }
        .stat-value { font-size: 2.5rem; font-weight: 700; }
        .stat-label { color: #888; font-size: 0.9rem; margin-top: 8px; text-transform: uppercase; letter-spacing: 1px; }
        .stat-card.critical .stat-value { color: #ff4757; }
        .stat-card.high .stat-value { color: #ff6b6b; }
        .stat-card.medium .stat-value { color: #ffa502; }
        .stat-card.low .stat-value { color: #20c997; }
        .issues-section {
            background: rgba(255,255,255,0.02);
            border-radius: 24px;
            padding: 30px;
            border: 1px solid rgba(255,255,255,0.08);
        }
        .section-title { font-size: 1.5rem; font-weight: 600; margin-bottom: 25px; }
        .issue-card {
            background: rgba(255,255,255,0.03);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #666;
            transition: all 0.3s ease;
        }
        .issue-card:hover { background: rgba(255,255,255,0.05); }
        .issue-card.critical { border-left-color: #ff4757; }
        .issue-card.high { border-left-color: #ff6b6b; }
        .issue-card.medium { border-left-color: #ffa502; }
        .issue-card.low { border-left-color: #20c997; }
        .issue-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .issue-type { font-weight: 600; font-size: 1.1rem; }
        .severity-pill {
            padding: 6px 16px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .severity-pill.critical { background: rgba(255,71,87,0.2); color: #ff4757; }
        .severity-pill.high { background: rgba(255,107,107,0.2); color: #ff6b6b; }
        .severity-pill.medium { background: rgba(255,165,2,0.2); color: #ffa502; }
        .severity-pill.low { background: rgba(32,201,151,0.2); color: #20c997; }
        .issue-location { color: #888; font-size: 0.9rem; margin-bottom: 10px; }
        .issue-snippet {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 12px 0;
        }
        .issue-desc { color: #aaa; font-size: 0.95rem; line-height: 1.6; }
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🔒 SASTify</div>
            <div class="subtitle">Security Analysis Report</div>
            <div>Generated: ${new Date().toLocaleString()}</div>
            <div class="risk-score ${riskLevel.toLowerCase()}">Overall Risk: ${riskLevel}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">${issues.length}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">${sc.Critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">${sc.High}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">${sc.Medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">${sc.Low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <div class="issues-section">
            <div class="section-title">Security Findings</div>
            ${issues.map((issue, idx) => `
                <div class="issue-card ${issue.severity.toLowerCase()}">
                    <div class="issue-header">
                        <span class="issue-type">#${idx + 1} ${this.escapeHtml(issue.type)}</span>
                        <span class="severity-pill ${issue.severity.toLowerCase()}">${issue.severity}</span>
                    </div>
                    <div class="issue-location">📁 ${this.escapeHtml(issue.file || 'Unknown')} : Line ${issue.line}</div>
                    <div class="issue-snippet">${this.escapeHtml(issue.snippet || '')}</div>
                    <div class="issue-desc">${this.escapeHtml(issue.description || issue.remediation || '')}</div>
                </div>
            `).join('')}
        </div>
        
        <div class="footer">
            <p>Generated by SASTify v1.0.0 • AI-Powered Security Analysis</p>
        </div>
    </div>
</body>
</html>`;
    }

    private escapeHtml(t: string): string {
        return t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    private async applyFixToEditor(fix: string, explanation: string, issueIndex: number): Promise<void> {
        const issue = this._scanResults.issues[issueIndex];
        if (!issue) {
            vscode.window.showErrorMessage('Issue not found.');
            return;
        }

        try {
            let fileUri: vscode.Uri | undefined;

            if (issue.file && path.isAbsolute(issue.file)) {
                fileUri = vscode.Uri.file(issue.file);
            } else if (issue.file) {
                const files = await vscode.workspace.findFiles(issue.file);
                if (files.length > 0) {
                    fileUri = files[0];
                } else if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                    fileUri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, issue.file);
                }
            }

            if (!fileUri) {
                vscode.window.showErrorMessage('Could not find file: ' + issue.file);
                return;
            }

            const document = await vscode.workspace.openTextDocument(fileUri);
            const editor = await vscode.window.showTextDocument(document, {
                viewColumn: vscode.ViewColumn.One,
                preserveFocus: true
            });

            const lineIndex = issue.line - 1;
            if (lineIndex < 0 || lineIndex >= document.lineCount) {
                vscode.window.showErrorMessage('Invalid line: ' + issue.line);
                return;
            }

            const startOffset = document.offsetAt(new vscode.Position(lineIndex, 0));
            const textFromLine = document.getText().substring(startOffset);
            const relativeIndex = textFromLine.indexOf(issue.snippet);

            if (relativeIndex === -1) {
                vscode.window.showErrorMessage('Could not locate the code snippet');
                return;
            }

            const range = new vscode.Range(
                document.positionAt(startOffset + relativeIndex),
                document.positionAt(startOffset + relativeIndex + issue.snippet.length)
            );

            const success = await editor.edit((eb: vscode.TextEditorEdit) => {
                eb.replace(range, fix);
            });

            if (success) {
                vscode.window.showInformationMessage('SASTify: Fix applied successfully!');
                this._panel.webview.postMessage({
                    command: 'fixApplied',
                    issueIndex: issueIndex
                });
            } else {
                vscode.window.showErrorMessage('Failed to apply fix.');
            }
        } catch (error: any) {
            vscode.window.showErrorMessage('Fix failed: ' + error.message);
        }
    }

    public dispose(): void {
        ResultsPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) { x.dispose(); }
        }
    }

    private _update(scanResults: any, filter?: any): void {
        const MAX = 100;
        let displayResults = Object.assign({}, scanResults);

        if (scanResults.issues && scanResults.issues.length > MAX) {
            const order: any = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
            const sorted = scanResults.issues.slice().sort((a: any, b: any) =>
                (order[a.severity] !== undefined ? order[a.severity] : 4) -
                (order[b.severity] !== undefined ? order[b.severity] : 4)
            );
            displayResults.issues = sorted.slice(0, MAX);
            displayResults.truncated = true;
            displayResults.totalIssuesCount = scanResults.issues.length;
            displayResults.displayedCount = MAX;
            displayResults.allIssues = scanResults.issues;
        }

        this._scanResults = displayResults;
        this._panel.webview.html = this._getHtmlForWebview(displayResults);
    }

    private _getHtmlForWebview(sr: any): string {
        const m = sr.metrics || {};
        const issuesJson = JSON.stringify(sr.issues || []);

        // Calculate risk score
        const totalRisk = (m.critical || 0) * 10 + (m.high || 0) * 5 + (m.medium || 0) * 2 + (m.low || 0);
        const riskLevel = totalRisk > 50 ? 'Critical' : totalRisk > 20 ? 'High' : totalRisk > 5 ? 'Medium' : 'Low';
        const riskPercent = Math.min(100, totalRisk * 2);

        const truncNotice = sr.truncated ? `
            <div class="truncation-notice">
                <span class="notice-icon">⚠️</span>
                <span>Showing ${sr.displayedCount} of ${sr.totalIssuesCount} issues. Export for full list.</span>
            </div>
        ` : '';

        let issuesHtml = '';
        if (sr.issues && sr.issues.length > 0) {
            // Group by file
            const groupedByFile: any = {};
            sr.issues.forEach((issue: any, index: number) => {
                const file = issue.file || 'Current File';
                if (!groupedByFile[file]) {
                    groupedByFile[file] = [];
                }
                groupedByFile[file].push({ ...issue, originalIndex: index });
            });

            for (const file in groupedByFile) {
                const fileIssues = groupedByFile[file];
                issuesHtml += `
                    <div class="file-group">
                        <div class="file-header" onclick="toggleFileGroup(this)">
                            <div class="file-info">
                                <span class="file-icon">📄</span>
                                <span class="file-name">${this.escapeHtml(file.split(/[\\/]/).pop() || file)}</span>
                                <span class="file-path">${this.escapeHtml(file)}</span>
                            </div>
                            <div class="file-stats">
                                <span class="issue-count">${fileIssues.length} issues</span>
                                <span class="expand-icon">▼</span>
                            </div>
                        </div>
                        <div class="file-issues">
                `;

                for (const issue of fileIssues) {
                    const index = issue.originalIndex;
                    const sev = issue.severity.toLowerCase();
                    const cweText = issue.cwe_id ? `<span class="cwe-badge">${issue.cwe_id}</span>` : '';

                    issuesHtml += `
                        <div class="issue-card ${sev}" data-index="${index}">
                            <div class="issue-header">
                                <div class="issue-title-row">
                                    <span class="issue-type">${this.escapeHtml(issue.type)}</span>
                                    ${cweText}
                                </div>
                                <span class="severity-badge ${sev}">${issue.severity}</span>
                            </div>
                            
                            <div class="issue-meta">
                                <span class="meta-item" onclick="goToLine('${this.escapeHtml(issue.file || '')}', ${issue.line})">
                                    <span class="meta-icon">📍</span> Line ${issue.line}
                                </span>
                                <span class="meta-item">
                                    <span class="meta-icon">🎯</span> ${((issue.confidence || 0) * 100).toFixed(0)}% confidence
                                </span>
                                <span class="meta-item">
                                    <span class="meta-icon">🔍</span> ${issue.scanner || 'ast'}
                                </span>
                            </div>
                            
                            <div class="code-snippet">
                                <div class="snippet-header">
                                    <span>Code</span>
                                    <button class="copy-btn" onclick="copySnippet(${index})">📋 Copy</button>
                                </div>
                                <pre><code>${this.escapeHtml(issue.snippet || '')}</code></pre>
                            </div>
                            
                            ${issue.description ? `<div class="issue-description">${this.escapeHtml(issue.description)}</div>` : ''}
                            
                            <div class="issue-actions">
                                <button class="action-btn primary" onclick="analyzeWithAI(${index})">
                                    <span class="btn-icon">🤖</span> Analyze with AI
                                </button>
                                <button class="action-btn secondary" onclick="goToLine('${this.escapeHtml(issue.file || '')}', ${issue.line})">
                                    <span class="btn-icon">↗️</span> Go to Code
                                </button>
                                <button class="action-btn ghost" onclick="reportFalsePositive(${index})">
                                    <span class="btn-icon">🚫</span> False Positive
                                </button>
                            </div>
                            
                            <div id="ai-analysis-${index}" class="ai-container"></div>
                        </div>
                    `;
                }

                issuesHtml += '</div></div>';
            }
        } else {
            issuesHtml = `
                <div class="empty-state">
                    <div class="empty-icon">🎉</div>
                    <h3>No Security Issues Found!</h3>
                    <p>Your code looks secure. Keep up the good work!</p>
                </div>
            `;
        }

        const css = `
            :root {
                --bg-dark: #0a0a0f;
                --bg-card: rgba(255,255,255,0.03);
                --bg-hover: rgba(255,255,255,0.06);
                --border-subtle: rgba(255,255,255,0.08);
                --border-hover: rgba(255,255,255,0.15);
                --text-primary: #f0f0f0;
                --text-secondary: #888;
                --accent-primary: #6366f1;
                --accent-secondary: #8b5cf6;
                --critical: #ef4444;
                --high: #f97316;
                --medium: #eab308;
                --low: #22c55e;
                --info: #3b82f6;
                --radius-sm: 6px;
                --radius-md: 12px;
                --radius-lg: 20px;
                --radius-full: 9999px;
                --shadow-glow: 0 0 40px rgba(99, 102, 241, 0.15);
            }
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: var(--bg-dark);
                color: var(--text-primary);
                line-height: 1.6;
                padding: 24px;
                min-height: 100vh;
            }
            
            .container { max-width: 1400px; margin: 0 auto; }
            
            /* Header */
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 24px 32px;
                background: var(--bg-card);
                border: 1px solid var(--border-subtle);
                border-radius: var(--radius-lg);
                margin-bottom: 24px;
                backdrop-filter: blur(20px);
            }
            
            .brand {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .brand-icon {
                width: 48px;
                height: 48px;
                background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
                border-radius: var(--radius-md);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 24px;
            }
            
            .brand-text h1 {
                font-size: 1.5rem;
                font-weight: 700;
                background: linear-gradient(90deg, #fff, #a5b4fc);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .brand-text p {
                font-size: 0.85rem;
                color: var(--text-secondary);
            }
            
            .header-actions {
                display: flex;
                gap: 12px;
            }
            
            /* Dashboard Stats */
            .dashboard {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 24px;
                margin-bottom: 24px;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 16px;
            }
            
            .stat-card {
                background: var(--bg-card);
                border: 1px solid var(--border-subtle);
                border-radius: var(--radius-md);
                padding: 20px;
                text-align: center;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .stat-card:hover {
                transform: translateY(-4px);
                border-color: var(--border-hover);
                box-shadow: var(--shadow-glow);
            }
            
            .stat-value {
                font-size: 2rem;
                font-weight: 700;
                line-height: 1;
            }
            
            .stat-label {
                font-size: 0.75rem;
                color: var(--text-secondary);
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-top: 8px;
            }
            
            .stat-card.total .stat-value { color: var(--accent-primary); }
            .stat-card.critical .stat-value { color: var(--critical); }
            .stat-card.high .stat-value { color: var(--high); }
            .stat-card.medium .stat-value { color: var(--medium); }
            .stat-card.low .stat-value { color: var(--low); }
            
            /* Risk Score */
            .risk-card {
                background: var(--bg-card);
                border: 1px solid var(--border-subtle);
                border-radius: var(--radius-md);
                padding: 24px;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }
            
            .risk-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 16px;
            }
            
            .risk-label { font-weight: 500; }
            
            .risk-level {
                padding: 6px 16px;
                border-radius: var(--radius-full);
                font-weight: 600;
                font-size: 0.85rem;
            }
            
            .risk-level.critical { background: rgba(239,68,68,0.2); color: var(--critical); }
            .risk-level.high { background: rgba(249,115,22,0.2); color: var(--high); }
            .risk-level.medium { background: rgba(234,179,8,0.2); color: var(--medium); }
            .risk-level.low { background: rgba(34,197,94,0.2); color: var(--low); }
            
            .risk-bar-container {
                height: 8px;
                background: rgba(255,255,255,0.1);
                border-radius: var(--radius-full);
                overflow: hidden;
            }
            
            .risk-bar {
                height: 100%;
                border-radius: var(--radius-full);
                transition: width 1s ease-out;
            }
            
            .risk-bar.critical { background: linear-gradient(90deg, var(--critical), var(--high)); }
            .risk-bar.high { background: linear-gradient(90deg, var(--high), var(--medium)); }
            .risk-bar.medium { background: linear-gradient(90deg, var(--medium), var(--low)); }
            .risk-bar.low { background: var(--low); }
            
            /* Controls */
            .controls {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px 20px;
                background: var(--bg-card);
                border: 1px solid var(--border-subtle);
                border-radius: var(--radius-md);
                margin-bottom: 24px;
            }
            
            .search-box {
                display: flex;
                align-items: center;
                gap: 8px;
                background: rgba(0,0,0,0.3);
                padding: 8px 16px;
                border-radius: var(--radius-full);
                border: 1px solid transparent;
                transition: all 0.2s;
            }
            
            .search-box:focus-within {
                border-color: var(--accent-primary);
            }
            
            .search-box input {
                background: transparent;
                border: none;
                color: var(--text-primary);
                font-size: 0.9rem;
                width: 200px;
                outline: none;
            }
            
            .filter-chips {
                display: flex;
                gap: 8px;
            }
            
            .chip {
                padding: 6px 14px;
                border-radius: var(--radius-full);
                font-size: 0.8rem;
                cursor: pointer;
                border: 1px solid var(--border-subtle);
                background: transparent;
                color: var(--text-secondary);
                transition: all 0.2s;
            }
            
            .chip:hover, .chip.active {
                background: var(--accent-primary);
                color: white;
                border-color: var(--accent-primary);
            }
            
            .export-btns {
                display: flex;
                gap: 8px;
            }
            
            /* Buttons */
            .btn {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 10px 18px;
                border-radius: var(--radius-full);
                font-weight: 500;
                font-size: 0.9rem;
                cursor: pointer;
                border: none;
                transition: all 0.2s;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
                color: white;
            }
            
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4);
            }
            
            .btn-secondary {
                background: rgba(255,255,255,0.08);
                color: var(--text-primary);
            }
            
            .btn-secondary:hover {
                background: rgba(255,255,255,0.12);
            }
            
            /* Truncation Notice */
            .truncation-notice {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 16px 20px;
                background: rgba(249,115,22,0.1);
                border: 1px solid rgba(249,115,22,0.3);
                border-radius: var(--radius-md);
                margin-bottom: 20px;
                color: var(--high);
            }
            
            /* File Groups */
            .file-group {
                margin-bottom: 16px;
                border: 1px solid var(--border-subtle);
                border-radius: var(--radius-md);
                overflow: hidden;
            }
            
            .file-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px 20px;
                background: var(--bg-card);
                cursor: pointer;
                transition: all 0.2s;
            }
            
            .file-header:hover { background: var(--bg-hover); }
            
            .file-info {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .file-icon { font-size: 1.2rem; }
            
            .file-name {
                font-weight: 600;
                color: var(--text-primary);
            }
            
            .file-path {
                font-size: 0.8rem;
                color: var(--text-secondary);
            }
            
            .file-stats {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .issue-count {
                padding: 4px 12px;
                background: rgba(255,255,255,0.1);
                border-radius: var(--radius-full);
                font-size: 0.8rem;
            }
            
            .expand-icon {
                transition: transform 0.3s;
            }
            
            .file-group.collapsed .expand-icon {
                transform: rotate(-90deg);
            }
            
            .file-group.collapsed .file-issues {
                display: none;
            }
            
            .file-issues {
                padding: 12px;
                background: rgba(0,0,0,0.2);
            }
            
            /* Issue Cards */
            .issue-card {
                background: var(--bg-card);
                border: 1px solid var(--border-subtle);
                border-radius: var(--radius-md);
                padding: 20px;
                margin-bottom: 12px;
                border-left: 4px solid var(--text-secondary);
                transition: all 0.3s;
            }
            
            .issue-card:hover {
                border-color: var(--border-hover);
                transform: translateX(4px);
            }
            
            .issue-card.critical { border-left-color: var(--critical); }
            .issue-card.high { border-left-color: var(--high); }
            .issue-card.medium { border-left-color: var(--medium); }
            .issue-card.low { border-left-color: var(--low); }
            
            .issue-header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 12px;
            }
            
            .issue-title-row {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .issue-type {
                font-weight: 600;
                font-size: 1rem;
            }
            
            .cwe-badge {
                padding: 2px 8px;
                background: rgba(59,130,246,0.2);
                color: var(--info);
                border-radius: var(--radius-sm);
                font-size: 0.75rem;
                font-weight: 500;
            }
            
            .severity-badge {
                padding: 4px 12px;
                border-radius: var(--radius-full);
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
            }
            
            .severity-badge.critical { background: rgba(239,68,68,0.2); color: var(--critical); }
            .severity-badge.high { background: rgba(249,115,22,0.2); color: var(--high); }
            .severity-badge.medium { background: rgba(234,179,8,0.2); color: var(--medium); }
            .severity-badge.low { background: rgba(34,197,94,0.2); color: var(--low); }
            
            .issue-meta {
                display: flex;
                gap: 16px;
                margin-bottom: 12px;
            }
            
            .meta-item {
                display: flex;
                align-items: center;
                gap: 4px;
                font-size: 0.85rem;
                color: var(--text-secondary);
                cursor: pointer;
            }
            
            .meta-item:hover { color: var(--accent-primary); }
            
            .code-snippet {
                background: rgba(0,0,0,0.4);
                border-radius: var(--radius-sm);
                overflow: hidden;
                margin: 12px 0;
            }
            
            .snippet-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 8px 12px;
                background: rgba(0,0,0,0.3);
                font-size: 0.8rem;
                color: var(--text-secondary);
            }
            
            .copy-btn {
                background: transparent;
                border: none;
                color: var(--text-secondary);
                cursor: pointer;
                font-size: 0.8rem;
            }
            
            .copy-btn:hover { color: var(--accent-primary); }
            
            .code-snippet pre {
                padding: 12px;
                overflow-x: auto;
                font-family: 'Fira Code', 'Cascadia Code', monospace;
                font-size: 0.85rem;
                line-height: 1.5;
            }
            
            .issue-description {
                font-size: 0.9rem;
                color: var(--text-secondary);
                margin-bottom: 12px;
            }
            
            .issue-actions {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
            }
            
            .action-btn {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 8px 14px;
                border-radius: var(--radius-full);
                font-size: 0.85rem;
                font-weight: 500;
                cursor: pointer;
                border: none;
                transition: all 0.2s;
            }
            
            .action-btn.primary {
                background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
                color: white;
            }
            
            .action-btn.secondary {
                background: rgba(255,255,255,0.08);
                color: var(--text-primary);
            }
            
            .action-btn.ghost {
                background: transparent;
                color: var(--text-secondary);
                border: 1px solid var(--border-subtle);
            }
            
            .action-btn:hover {
                transform: translateY(-1px);
            }
            
            /* AI Analysis Container */
            .ai-container {
                margin-top: 16px;
            }
            
            .ai-analysis {
                background: rgba(99,102,241,0.1);
                border: 1px solid rgba(99,102,241,0.3);
                border-radius: var(--radius-md);
                padding: 16px;
                margin-top: 12px;
            }
            
            .ai-header {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 12px;
                font-weight: 600;
            }
            
            .ai-confirmed { color: var(--critical); }
            .ai-fp { color: var(--low); }
            
            .ai-content p {
                margin: 8px 0;
                font-size: 0.9rem;
            }
            
            .ai-fix {
                background: rgba(0,0,0,0.3);
                border-radius: var(--radius-sm);
                padding: 12px;
                margin: 12px 0;
            }
            
            .ai-fix pre {
                font-family: 'Fira Code', monospace;
                font-size: 0.85rem;
                white-space: pre-wrap;
            }
            
            /* Loading State */
            .loading {
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 24px;
                gap: 12px;
            }
            
            .spinner {
                width: 32px;
                height: 32px;
                border: 3px solid var(--border-subtle);
                border-top-color: var(--accent-primary);
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            /* Empty State */
            .empty-state {
                text-align: center;
                padding: 60px 20px;
            }
            
            .empty-icon {
                font-size: 4rem;
                margin-bottom: 16px;
            }
            
            .empty-state h3 {
                font-size: 1.5rem;
                margin-bottom: 8px;
                color: var(--low);
            }
            
            .empty-state p {
                color: var(--text-secondary);
            }
            
            /* FP Box */
            .fp-box {
                background: rgba(34,197,94,0.1);
                border: 1px solid rgba(34,197,94,0.3);
                border-radius: var(--radius-md);
                padding: 16px;
            }
            
            /* Toast */
            .toast {
                position: fixed;
                bottom: 24px;
                right: 24px;
                background: var(--bg-card);
                border: 1px solid var(--accent-primary);
                padding: 12px 20px;
                border-radius: var(--radius-md);
                display: none;
                animation: slideIn 0.3s ease;
            }
            
            @keyframes slideIn {
                from { transform: translateY(20px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
        `;

        const script = `
            const vscode = acquireVsCodeApi();
            const issuesData = ${issuesJson};
            
            // Toggle file group
            function toggleFileGroup(header) {
                const group = header.parentElement;
                group.classList.toggle('collapsed');
            }
            
            // Go to line
            function goToLine(file, line) {
                vscode.postMessage({ command: 'goToLine', file: file, line: line });
            }
            
            // Copy snippet
            function copySnippet(idx) {
                const issue = issuesData[idx];
                if (issue && issue.snippet) {
                    navigator.clipboard.writeText(issue.snippet);
                    showToast('Copied to clipboard!');
                }
            }
            
            // Export
            function exportResults(format) {
                vscode.postMessage({ command: 'exportResults', format: format });
            }
            
            // AI Analysis
            function analyzeWithAI(idx) {
                const issue = issuesData[idx];
                if (!issue) return;
                
                document.getElementById('ai-analysis-' + idx).innerHTML = 
                    '<div class="loading"><div class="spinner"></div><span>AI analyzing vulnerability...</span></div>';
                
                vscode.postMessage({ 
                    command: 'analyzeWithAI', 
                    issueIndex: idx, 
                    codeSnippet: issue.snippet 
                });
            }
            
            // Report FP
            function reportFalsePositive(idx) {
                const comment = prompt('Why is this a false positive? (Optional)');
                if (comment !== null) {
                    vscode.postMessage({ 
                        command: 'reportFalsePositive', 
                        issueIndex: idx, 
                        comment: comment 
                    });
                }
            }
            
            // Apply fix
            function applyFix(fix, explanation, idx) {
                vscode.postMessage({ 
                    command: 'applyFix', 
                    fix: fix, 
                    explanation: explanation, 
                    issueIndex: idx 
                });
            }
            
            // Toast notification
            function showToast(message) {
                const toast = document.getElementById('toast');
                toast.textContent = message;
                toast.style.display = 'block';
                setTimeout(() => { toast.style.display = 'none'; }, 2000);
            }
            
            // Search filter
            document.getElementById('search-input')?.addEventListener('input', function(e) {
                const query = e.target.value.toLowerCase();
                document.querySelectorAll('.issue-card').forEach(card => {
                    const text = card.textContent.toLowerCase();
                    card.style.display = text.includes(query) ? 'block' : 'none';
                });
            });
            
            // Message handler
            window.addEventListener('message', function(event) {
                const msg = event.data;
                
                if (msg.command === 'aiAnalysisResult') {
                    const a = msg.analysis;
                    const container = document.getElementById('ai-analysis-' + msg.issueIndex);
                    
                    if (a.error) {
                        container.innerHTML = '<div class="ai-analysis" style="border-color: var(--critical);"><p style="color: var(--critical);">Error: ' + a.error + '</p></div>';
                        return;
                    }
                    
                    const conf = ((a.confidence || 0) * 100).toFixed(0);
                    let html;
                    
                    if (!a.is_confirmed) {
                        html = '<div class="fp-box">';
                        html += '<div class="ai-header ai-fp">✓ Likely False Positive</div>';
                        html += '<div class="ai-content">';
                        html += '<p><strong>Confidence:</strong> ' + conf + '%</p>';
                        html += '<p><strong>Risk Level:</strong> ' + (a.risk_level || 'Low') + '</p>';
                        html += '<p>' + (a.explanation || 'AI analysis suggests this is likely safe.') + '</p>';
                        html += '</div></div>';
                    } else {
                        html = '<div class="ai-analysis">';
                        html += '<div class="ai-header ai-confirmed">⚠️ Confirmed Vulnerability</div>';
                        html += '<div class="ai-content">';
                        html += '<p><strong>Confidence:</strong> ' + conf + '%</p>';
                        html += '<p><strong>Risk Level:</strong> ' + (a.risk_level || 'Unknown') + '</p>';
                        html += '<p>' + (a.explanation || '') + '</p>';
                        
                        if (a.suggested_fix) {
                            html += '<div class="ai-fix"><strong>Suggested Fix:</strong><pre>' + a.suggested_fix + '</pre></div>';
                            html += '<button class="action-btn primary" onclick="applyFix(decodeURIComponent(\\'' + encodeURIComponent(a.suggested_fix) + '\\'), decodeURIComponent(\\'' + encodeURIComponent(a.explanation || '') + '\\'), ' + msg.issueIndex + ')">Apply Fix</button>';
                        }
                        
                        html += '</div></div>';
                    }
                    
                    container.innerHTML = html;
                } else if (msg.command === 'aiAnalysisError') {
                    document.getElementById('ai-analysis-' + msg.issueIndex).innerHTML = 
                        '<div class="ai-analysis" style="border-color: var(--critical);"><p style="color: var(--critical);">Error: ' + msg.error + '</p></div>';
                } else if (msg.command === 'falsePositiveReported') {
                    showToast('False positive reported. Thanks!');
                } else if (msg.command === 'fixApplied') {
                    showToast('Fix applied successfully!');
                }
            });
        `;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SASTify Security Results</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>${css}</style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="brand">
                <div class="brand-icon">🔒</div>
                <div class="brand-text">
                    <h1>SASTify</h1>
                    <p>AI-Powered Security Analysis</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn btn-secondary" onclick="exportResults('json')">📄 Export JSON</button>
                <button class="btn btn-secondary" onclick="exportResults('sarif')">📊 Export SARIF</button>
                <button class="btn btn-primary" onclick="exportResults('html')">📑 Export Report</button>
            </div>
        </div>
        
        <!-- Dashboard -->
        <div class="dashboard">
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="stat-value">${m.total_issues || 0}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-value">${m.critical || 0}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-value">${m.high || 0}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-value">${m.medium || 0}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-value">${m.low || 0}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            <div class="risk-card">
                <div class="risk-header">
                    <span class="risk-label">Overall Security Risk</span>
                    <span class="risk-level ${riskLevel.toLowerCase()}">${riskLevel}</span>
                </div>
                <div class="risk-bar-container">
                    <div class="risk-bar ${riskLevel.toLowerCase()}" style="width: ${riskPercent}%"></div>
                </div>
            </div>
        </div>
        
        <!-- Controls -->
        <div class="controls">
            <div class="search-box">
                <span>🔍</span>
                <input type="text" id="search-input" placeholder="Search issues...">
            </div>
            <div class="filter-chips">
                <span class="chip active" onclick="this.classList.toggle('active')">All</span>
                <span class="chip" onclick="this.classList.toggle('active')">Critical</span>
                <span class="chip" onclick="this.classList.toggle('active')">High</span>
                <span class="chip" onclick="this.classList.toggle('active')">Medium</span>
                <span class="chip" onclick="this.classList.toggle('active')">Low</span>
            </div>
        </div>
        
        <!-- Issues -->
        ${truncNotice}
        ${issuesHtml}
    </div>
    
    <div id="toast" class="toast"></div>
    
    <script>${script}</script>
</body>
</html>`;
    }
}