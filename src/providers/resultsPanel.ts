import * as vscode from 'vscode';
import { TmasScanResult, TmasVulnerability, TmasSecret, TmasMalware, flattenFindings } from '../scanners/tmas';
import { TemplateScanResult, TemplateScanFinding } from '../scanners/templateScanner';

interface Finding {
    id: string;
    ruleId: string;
    type: 'vulnerability' | 'secret' | 'malware' | 'iac';
    severity: string;
    title: string;
    description: string;
    file?: string;
    line?: number;
    resource?: string;
    resolution?: string;
    link?: string;
    service?: string;
    provider?: string;
    complianceStandards?: Array<{ id: string; name?: string }>;
    fixAvailable?: boolean;
    fixVersion?: string;
    installedVersion?: string;
}

interface SeverityCounts {
    extreme: number;
    veryHigh: number;
    high: number;
    medium: number;
    low: number;
}

export class ResultsPanelProvider {
    public static currentPanel: ResultsPanelProvider | undefined;
    private readonly panel: vscode.WebviewPanel;
    private findings: Finding[] = [];
    private disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel, private extensionUri: vscode.Uri) {
        this.panel = panel;

        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'openFile':
                        if (message.file) {
                            const uri = vscode.Uri.file(message.file);
                            const doc = await vscode.workspace.openTextDocument(uri);
                            const editor = await vscode.window.showTextDocument(doc);
                            if (message.line) {
                                const line = Math.max(0, message.line - 1);
                                const range = new vscode.Range(line, 0, line, 0);
                                editor.selection = new vscode.Selection(range.start, range.end);
                                editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
                            }
                        }
                        break;
                    case 'openLink':
                        if (message.url) {
                            vscode.env.openExternal(vscode.Uri.parse(message.url));
                        }
                        break;
                }
            },
            null,
            this.disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri): ResultsPanelProvider {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (ResultsPanelProvider.currentPanel) {
            ResultsPanelProvider.currentPanel.panel.reveal(column);
            return ResultsPanelProvider.currentPanel;
        }

        const panel = vscode.window.createWebviewPanel(
            'trendaiResults',
            'TrendAI™ Security Results',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [extensionUri]
            }
        );

        ResultsPanelProvider.currentPanel = new ResultsPanelProvider(panel, extensionUri);
        return ResultsPanelProvider.currentPanel;
    }

    public addTmasResults(result: TmasScanResult, filePath: string): void {
        // Add vulnerabilities (findings can be grouped by severity)
        const vulnFindings = flattenFindings<TmasVulnerability>(result.vulnerabilities?.findings);
        for (const vuln of vulnFindings) {
            this.findings.push(this.convertVulnerability(vuln, filePath));
        }

        // Add secrets (findings can be grouped by severity)
        const secretFindings = flattenFindings<TmasSecret>(result.secrets?.findings);
        for (const secret of secretFindings) {
            this.findings.push(this.convertSecret(secret, filePath));
        }

        // Add malware
        const malwareFindings = flattenFindings<TmasMalware>(result.malware?.findings);
        for (const malware of malwareFindings) {
            if (malware.foundMalwares) {
                for (const m of malware.foundMalwares) {
                    this.findings.push({
                        id: m.fileSHA256 || 'malware',
                        ruleId: m.malwareName,
                        type: 'malware',
                        severity: 'critical',
                        title: m.malwareName,
                        description: `Malware detected in ${malware.fileName || 'file'}`,
                        file: malware.fileName,
                        resolution: 'Remove the infected file immediately and scan your system for additional threats.'
                    });
                }
            }
        }

        this.updatePanel();
    }

    public addTemplateResults(result: TemplateScanResult, filePath: string): void {
        for (const finding of result.findings) {
            this.findings.push(this.convertIaCFinding(finding, filePath));
        }
        this.updatePanel();
    }

    public clear(): void {
        this.findings = [];
        this.updatePanel();
    }

    private convertVulnerability(vuln: TmasVulnerability, filePath: string): Finding {
        const packageName = vuln.name || vuln.packageName || 'unknown package';
        const fixVersion = vuln.fix && vuln.fix !== 'not-fixed' ? vuln.fix : vuln.fixedVersion;
        const hasFixAvailable = !!fixVersion;
        const installedVersion = vuln.version || vuln.installedVersion;

        return {
            id: vuln.id,
            ruleId: vuln.id,
            type: 'vulnerability',
            severity: vuln.severity?.toLowerCase() || 'medium',
            title: `${vuln.id} in ${packageName}`,
            description: vuln.title || vuln.description || `Vulnerability in ${packageName} version ${installedVersion || 'unknown'}`,
            file: filePath,
            resource: packageName,
            resolution: fixVersion
                ? `Update ${packageName} to version ${fixVersion} or later.`
                : 'No fix available. Check vendor advisories for patches or workarounds.',
            link: vuln.source || vuln.link || `https://nvd.nist.gov/vuln/detail/${vuln.id}`,
            fixAvailable: hasFixAvailable,
            fixVersion: fixVersion || undefined,
            installedVersion: installedVersion
        };
    }

    private convertSecret(secret: TmasSecret, basePath: string): Finding {
        return {
            id: secret.ruleID,
            ruleId: secret.ruleID,
            type: 'secret',
            severity: 'high',
            title: secret.ruleID,
            description: secret.description || 'Secret or credential detected in code',
            file: secret.file ? `${basePath}/${secret.file}` : basePath,
            line: secret.startLine,
            resolution: '1. Rotate the exposed credential immediately.\n2. Remove the secret from code.\n3. Use environment variables or a secrets manager.\n4. Add the file to .gitignore if appropriate.'
        };
    }

    private convertIaCFinding(finding: TemplateScanFinding, filePath: string): Finding {
        return {
            id: finding.ruleId,
            ruleId: finding.ruleId,
            type: 'iac',
            severity: finding.severity?.toLowerCase() || 'medium',
            title: finding.ruleName || finding.ruleId,
            description: finding.description || 'Infrastructure misconfiguration detected',
            file: finding.file || filePath,
            line: finding.line,
            resource: finding.resource,
            resolution: finding.recommendation || this.getDefaultIaCResolution(finding.ruleId, finding.ruleName),
            link: finding.link,
            service: finding.checkDetails?.service,
            provider: finding.checkDetails?.provider,
            complianceStandards: finding.checkDetails?.complianceStandards
        };
    }

    private getDefaultIaCResolution(ruleId: string, ruleName?: string): string {
        const name = (ruleName || ruleId).toLowerCase();

        if (name.includes('encrypt')) {
            return 'Enable encryption at rest using AWS KMS or similar service.';
        }
        if (name.includes('public')) {
            return 'Restrict public access by updating bucket policies and enabling Block Public Access settings.';
        }
        if (name.includes('logging')) {
            return 'Enable access logging to monitor and audit resource access.';
        }
        if (name.includes('versioning')) {
            return 'Enable versioning to protect against accidental deletions and overwrites.';
        }
        if (name.includes('ssl') || name.includes('tls') || name.includes('https')) {
            return 'Enforce HTTPS/TLS connections and disable insecure protocols.';
        }

        return 'Review the security best practices for this resource type and update the configuration accordingly.';
    }

    private getSeverityCounts(): SeverityCounts {
        const counts: SeverityCounts = {
            extreme: 0,
            veryHigh: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        for (const finding of this.findings) {
            const severity = finding.severity.toLowerCase();
            if (severity === 'extreme' || severity === 'critical') {
                counts.extreme++;
            } else if (severity === 'very_high' || severity === 'very high' || severity === 'veryhigh') {
                counts.veryHigh++;
            } else if (severity === 'high') {
                counts.high++;
            } else if (severity === 'medium') {
                counts.medium++;
            } else {
                counts.low++;
            }
        }

        return counts;
    }

    private mapSeverityDisplay(severity: string): string {
        const s = severity.toLowerCase();
        if (s === 'extreme' || s === 'critical') return 'Extreme';
        if (s === 'very_high' || s === 'very high' || s === 'veryhigh') return 'Very High';
        if (s === 'high') return 'High';
        if (s === 'medium') return 'Medium';
        return 'Low';
    }

    private getSeverityClass(severity: string): string {
        const s = severity.toLowerCase();
        if (s === 'extreme' || s === 'critical') return 'extreme';
        if (s === 'very_high' || s === 'very high' || s === 'veryhigh') return 'veryHigh';
        if (s === 'high') return 'high';
        if (s === 'medium') return 'medium';
        return 'low';
    }

    private updatePanel(): void {
        this.panel.webview.html = this.getHtmlContent();
    }

    private getHtmlContent(): string {
        const counts = this.getSeverityCounts();
        const total = this.findings.length;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrendAI™ Security Results</title>
    <style>
        :root {
            --extreme-color: #dc2626;
            --veryHigh-color: #ea580c;
            --high-color: #f59e0b;
            --medium-color: #eab308;
            --low-color: #22c55e;
            --bg-color: var(--vscode-editor-background);
            --text-color: var(--vscode-editor-foreground);
            --border-color: var(--vscode-panel-border);
            --card-bg: var(--vscode-editorWidget-background);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--text-color);
            background: var(--bg-color);
            padding: 20px;
            line-height: 1.5;
        }

        .header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }

        .header h1 {
            font-size: 1.5em;
            font-weight: 600;
        }

        .header .total {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9em;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .severity-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .severity-card .count {
            font-size: 2em;
            font-weight: 700;
            min-width: 50px;
        }

        .severity-card .label {
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 0.5px;
            opacity: 0.8;
        }

        .severity-card.extreme { border-left: 4px solid var(--extreme-color); }
        .severity-card.extreme .count { color: var(--extreme-color); }

        .severity-card.veryHigh { border-left: 4px solid var(--veryHigh-color); }
        .severity-card.veryHigh .count { color: var(--veryHigh-color); }

        .severity-card.high { border-left: 4px solid var(--high-color); }
        .severity-card.high .count { color: var(--high-color); }

        .severity-card.medium { border-left: 4px solid var(--medium-color); }
        .severity-card.medium .count { color: var(--medium-color); }

        .severity-card.low { border-left: 4px solid var(--low-color); }
        .severity-card.low .count { color: var(--low-color); }

        .chart-container {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }

        .chart-container h2 {
            font-size: 1.1em;
            margin-bottom: 16px;
        }

        .bar-chart {
            display: flex;
            height: 32px;
            border-radius: 4px;
            overflow: hidden;
            background: var(--border-color);
        }

        .bar-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.75em;
            font-weight: 600;
            transition: all 0.3s;
        }

        .bar-segment:hover {
            filter: brightness(1.1);
        }

        .bar-segment.extreme { background: var(--extreme-color); }
        .bar-segment.veryHigh { background: var(--veryHigh-color); }
        .bar-segment.high { background: var(--high-color); }
        .bar-segment.medium { background: var(--medium-color); }
        .bar-segment.low { background: var(--low-color); }

        .legend {
            display: flex;
            gap: 16px;
            margin-top: 12px;
            flex-wrap: wrap;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.85em;
        }

        .legend-dot {
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }

        .filters {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }

        .filter-btn {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 6px 14px;
            border-radius: 16px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.2s;
        }

        .filter-btn:hover {
            background: var(--vscode-button-hoverBackground);
        }

        .filter-btn.active {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border-color: var(--vscode-button-background);
        }

        .controls-row {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .view-controls {
            display: flex;
            gap: 8px;
        }

        .view-btn {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
            opacity: 0.8;
        }

        .view-btn:hover {
            opacity: 1;
            background: var(--vscode-list-hoverBackground);
        }

        .section-title {
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
        }

        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .finding-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }

        .finding-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 16px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .finding-header:hover {
            background: var(--vscode-list-hoverBackground);
        }

        .severity-badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }

        .severity-badge.extreme { background: var(--extreme-color); }
        .severity-badge.veryHigh { background: var(--veryHigh-color); }
        .severity-badge.high { background: var(--high-color); }
        .severity-badge.medium { background: var(--medium-color); }
        .severity-badge.low { background: var(--low-color); }

        .type-badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            text-transform: uppercase;
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
        }

        .fix-badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: 600;
        }

        .fix-badge.has-fix {
            background: #22c55e;
            color: white;
        }

        .fix-badge.no-fix {
            background: #6b7280;
            color: white;
        }

        .version-info {
            font-size: 0.8em;
            opacity: 0.8;
            margin-left: auto;
            white-space: nowrap;
        }

        .finding-title {
            flex: 1;
            font-weight: 500;
        }

        .finding-location {
            font-size: 0.85em;
            opacity: 0.7;
            cursor: pointer;
        }

        .finding-location:hover {
            text-decoration: underline;
            opacity: 1;
        }

        .expand-icon {
            opacity: 0.5;
            transition: transform 0.2s;
        }

        .finding-card.expanded .expand-icon {
            transform: rotate(90deg);
        }

        .finding-details {
            display: none;
            padding: 0 16px 16px;
            border-top: 1px solid var(--border-color);
        }

        .finding-card.expanded .finding-details {
            display: block;
        }

        .detail-section {
            margin-top: 12px;
        }

        .detail-section h4 {
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.7;
            margin-bottom: 6px;
        }

        .detail-section p {
            font-size: 0.95em;
        }

        .resolution-box {
            background: var(--vscode-textBlockQuote-background);
            border-left: 3px solid var(--vscode-textBlockQuote-border);
            padding: 12px;
            border-radius: 0 4px 4px 0;
            white-space: pre-wrap;
        }

        .finding-meta {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            padding: 8px 0;
            margin-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.85em;
        }

        .meta-item {
            color: var(--text-color);
            opacity: 0.9;
        }

        .meta-item strong {
            opacity: 0.7;
        }

        .compliance-tags {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 12px;
        }

        .compliance-tag {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 500;
        }

        .link-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-top: 12px;
            padding: 6px 12px;
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
        }

        .link-btn:hover {
            background: var(--vscode-button-secondaryHoverBackground);
        }

        /* Resource Group Styles */
        .resource-group {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }

        .resource-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 16px;
            cursor: pointer;
            transition: background 0.2s;
            border-left: 4px solid var(--border-color);
        }

        .resource-header:hover {
            background: var(--vscode-list-hoverBackground);
        }

        .resource-header.extreme { border-left-color: var(--extreme-color); }
        .resource-header.veryHigh { border-left-color: var(--veryHigh-color); }
        .resource-header.high { border-left-color: var(--high-color); }
        .resource-header.medium { border-left-color: var(--medium-color); }
        .resource-header.low { border-left-color: var(--low-color); }

        .resource-icon {
            font-size: 1.2em;
        }

        .resource-name {
            flex: 1;
            font-weight: 600;
            font-size: 1em;
        }

        .resource-count {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 0.8em;
        }

        .resource-expand-icon {
            opacity: 0.5;
            transition: transform 0.2s;
        }

        .resource-group.collapsed .resource-expand-icon {
            transform: rotate(-90deg);
        }

        .resource-group.collapsed .resource-findings {
            display: none;
        }

        .resource-findings {
            border-top: 1px solid var(--border-color);
            padding: 8px;
        }

        .resource-findings .finding-card {
            margin-bottom: 8px;
            border: 1px solid var(--border-color);
        }

        .resource-findings .finding-card:last-child {
            margin-bottom: 0;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            opacity: 0.7;
        }

        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ TrendAI™ Security Results</h1>
        <span class="total">${total} issues found</span>
    </div>

    ${total === 0 ? this.getEmptyState() : `
    <div class="summary">
        <div class="severity-card extreme">
            <div class="count">${counts.extreme}</div>
            <div class="label">Extreme</div>
        </div>
        <div class="severity-card veryHigh">
            <div class="count">${counts.veryHigh}</div>
            <div class="label">Very High</div>
        </div>
        <div class="severity-card high">
            <div class="count">${counts.high}</div>
            <div class="label">High</div>
        </div>
        <div class="severity-card medium">
            <div class="count">${counts.medium}</div>
            <div class="label">Medium</div>
        </div>
        <div class="severity-card low">
            <div class="count">${counts.low}</div>
            <div class="label">Low</div>
        </div>
    </div>

    <div class="chart-container">
        <h2>Severity Distribution</h2>
        <div class="bar-chart">
            ${this.getBarSegments(counts, total)}
        </div>
        <div class="legend">
            <div class="legend-item"><div class="legend-dot" style="background: var(--extreme-color)"></div> Extreme</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--veryHigh-color)"></div> Very High</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--high-color)"></div> High</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--medium-color)"></div> Medium</div>
            <div class="legend-item"><div class="legend-dot" style="background: var(--low-color)"></div> Low</div>
        </div>
    </div>

    <div class="controls-row">
        <div class="filters">
            <button class="filter-btn active" onclick="filterBy('all')">All (${total})</button>
            <button class="filter-btn" onclick="filterBy('extreme')">Extreme (${counts.extreme})</button>
            <button class="filter-btn" onclick="filterBy('veryHigh')">Very High (${counts.veryHigh})</button>
            <button class="filter-btn" onclick="filterBy('high')">High (${counts.high})</button>
            <button class="filter-btn" onclick="filterBy('medium')">Medium (${counts.medium})</button>
            <button class="filter-btn" onclick="filterBy('low')">Low (${counts.low})</button>
        </div>
        <div class="view-controls">
            <button class="view-btn" onclick="expandAll()">Expand All</button>
            <button class="view-btn" onclick="collapseAll()">Collapse All</button>
        </div>
    </div>

    <h2 class="section-title">Findings by Resource</h2>

    <div class="findings-list">
        ${this.getFindingsHtml()}
    </div>
    `}

    <script>
        const vscode = acquireVsCodeApi();

        function toggleFinding(id) {
            const card = document.getElementById('finding-' + id);
            card.classList.toggle('expanded');
        }

        function toggleResource(resource) {
            const groups = document.querySelectorAll('.resource-group');
            groups.forEach(group => {
                if (group.dataset.resource === resource) {
                    group.classList.toggle('collapsed');
                }
            });
        }

        function openFile(file, line) {
            vscode.postMessage({ command: 'openFile', file, line });
        }

        function openLink(url) {
            vscode.postMessage({ command: 'openLink', url });
        }

        function filterBy(severity) {
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            // Filter findings
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                if (severity === 'all' || card.dataset.severity === severity) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });

            // Hide resource groups with no visible findings
            const groups = document.querySelectorAll('.resource-group');
            groups.forEach(group => {
                const visibleFindings = group.querySelectorAll('.finding-card[style="display: block"], .finding-card:not([style*="display"])');
                const hasVisible = Array.from(group.querySelectorAll('.finding-card')).some(card => {
                    return severity === 'all' || card.dataset.severity === severity;
                });
                group.style.display = hasVisible ? 'block' : 'none';
            });
        }

        function expandAll() {
            document.querySelectorAll('.resource-group').forEach(g => g.classList.remove('collapsed'));
        }

        function collapseAll() {
            document.querySelectorAll('.resource-group').forEach(g => g.classList.add('collapsed'));
        }
    </script>
</body>
</html>`;
    }

    private getEmptyState(): string {
        return `
        <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <h2>No Issues Found</h2>
            <p>Run a scan to see security findings here.</p>
        </div>`;
    }

    private getBarSegments(counts: SeverityCounts, total: number): string {
        if (total === 0) return '';

        const segments: string[] = [];
        const severities: (keyof SeverityCounts)[] = ['extreme', 'veryHigh', 'high', 'medium', 'low'];

        for (const severity of severities) {
            const count = counts[severity];
            if (count > 0) {
                const percent = (count / total) * 100;
                segments.push(`<div class="bar-segment ${severity}" style="width: ${percent}%">${count}</div>`);
            }
        }

        return segments.join('');
    }

    private getFindingsHtml(): string {
        // Group findings by resource
        const grouped = new Map<string, Finding[]>();

        for (const finding of this.findings) {
            const resource = finding.resource || 'Other';
            if (!grouped.has(resource)) {
                grouped.set(resource, []);
            }
            grouped.get(resource)!.push(finding);
        }

        // Sort resources by highest severity finding
        const sortedResources = Array.from(grouped.entries()).sort((a, b) => {
            const aMax = Math.max(...a[1].map(f => this.severityToNumber(f.severity)));
            const bMax = Math.max(...b[1].map(f => this.severityToNumber(f.severity)));
            return bMax - aMax;
        });

        let html = '';
        let findingIndex = 0;

        for (const [resource, findings] of sortedResources) {
            // Get highest severity for resource header color
            const highestSev = findings.reduce((max, f) =>
                this.severityToNumber(f.severity) > this.severityToNumber(max.severity) ? f : max
            );
            const resourceSevClass = this.getSeverityClass(highestSev.severity);

            html += `
            <div class="resource-group" data-resource="${this.escapeHtml(resource)}">
                <div class="resource-header ${resourceSevClass}" onclick="toggleResource('${this.escapeHtml(resource).replace(/'/g, "\\'")}')">
                    <span class="resource-icon">📦</span>
                    <span class="resource-name">${this.escapeHtml(resource)}</span>
                    <span class="resource-count">${findings.length} issue${findings.length !== 1 ? 's' : ''}</span>
                    <span class="resource-expand-icon">▼</span>
                </div>
                <div class="resource-findings">`;

            for (const finding of findings) {
                const sevClass = this.getSeverityClass(finding.severity);
                const sevDisplay = this.mapSeverityDisplay(finding.severity);

                const fixBadgeHtml = finding.type === 'vulnerability'
                    ? (finding.fixAvailable
                        ? `<span class="fix-badge has-fix" title="Fix: ${this.escapeHtml(finding.fixVersion || '')}">FIX</span>`
                        : `<span class="fix-badge no-fix">NO FIX</span>`)
                    : '';

                const versionHtml = finding.type === 'vulnerability' && finding.installedVersion
                    ? `<span class="version-info">${this.escapeHtml(finding.installedVersion)}${finding.fixAvailable ? ' → ' + this.escapeHtml(finding.fixVersion || '') : ''}</span>`
                    : '';

                html += `
                    <div class="finding-card" id="finding-${findingIndex}" data-severity="${sevClass}">
                        <div class="finding-header" onclick="toggleFinding(${findingIndex})">
                            <span class="severity-badge ${sevClass}">${sevDisplay}</span>
                            <span class="type-badge">${finding.type}</span>
                            ${fixBadgeHtml}
                            <span class="finding-title">${this.escapeHtml(finding.title)}</span>
                            ${versionHtml}
                            ${finding.file ? `<span class="finding-location" onclick="event.stopPropagation(); openFile('${this.escapeHtml(finding.file)}', ${finding.line || 1})">${this.getShortPath(finding.file)}${finding.line ? ':' + finding.line : ''}</span>` : ''}
                            <span class="expand-icon">▶</span>
                        </div>
                        <div class="finding-details">
                            <div class="finding-meta">
                                <span class="meta-item"><strong>Rule ID:</strong> ${this.escapeHtml(finding.ruleId)}</span>
                                ${finding.service ? `<span class="meta-item"><strong>Service:</strong> ${this.escapeHtml(finding.service)}</span>` : ''}
                                ${finding.provider ? `<span class="meta-item"><strong>Provider:</strong> ${this.escapeHtml(finding.provider.toUpperCase())}</span>` : ''}
                            </div>
                            ${finding.complianceStandards && finding.complianceStandards.length > 0 ? `
                            <div class="compliance-tags">
                                ${finding.complianceStandards.map(c => `<span class="compliance-tag">${this.escapeHtml(c.id)}</span>`).join('')}
                            </div>
                            ` : ''}
                            <div class="detail-section">
                                <h4>Description</h4>
                                <p>${this.escapeHtml(finding.description)}</p>
                            </div>
                            <div class="detail-section">
                                <h4>Resolution</h4>
                                <div class="resolution-box">${this.escapeHtml(finding.resolution || 'No resolution available.')}</div>
                            </div>
                            ${finding.link ? `<button class="link-btn" onclick="openLink('${this.escapeHtml(finding.link)}')">📖 Learn More</button>` : ''}
                        </div>
                    </div>`;
                findingIndex++;
            }

            html += `
                </div>
            </div>`;
        }

        return html;
    }

    private severityToNumber(severity: string): number {
        const s = severity.toLowerCase();
        if (s === 'extreme' || s === 'critical') return 5;
        if (s === 'very_high' || s === 'very high' || s === 'veryhigh') return 4;
        if (s === 'high') return 3;
        if (s === 'medium') return 2;
        return 1;
    }

    private getShortPath(filePath: string): string {
        const parts = filePath.split('/');
        return parts.length > 2 ? `.../${parts.slice(-2).join('/')}` : filePath;
    }

    private escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    public dispose(): void {
        ResultsPanelProvider.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            const disposable = this.disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
