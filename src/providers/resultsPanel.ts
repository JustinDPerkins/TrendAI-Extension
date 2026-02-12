import * as vscode from 'vscode';
import { TmasScanResult, TmasVulnerability, TmasSecret, TmasMalware, flattenFindings } from '../scanners/tmas';
import { TemplateScanResult, TemplateScanFinding } from '../scanners/templateScanner';
import { LLMScanResult, LLMAttackResult } from '../scanners/llmScanner';

interface Finding {
    id: string;
    ruleId: string;
    type: 'vulnerability' | 'secret' | 'malware' | 'iac' | 'llm';
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
    // LLM-specific fields
    attackPrompt?: string;
    modelResponse?: string;
    technique?: string;
    modifier?: string;
    evaluation?: string;
}

interface SeverityCounts {
    extreme: number;
    veryHigh: number;
    high: number;
    medium: number;
    low: number;
}

export interface ScanError {
    code: string;
    message: string;
    details?: string;
    file?: string;
    timestamp: string;
}

export interface ScanSummary {
    totalFiles: number;
    successfulScans: number;
    failedScans: number;
    errors: ScanError[];
}

export class ResultsPanelProvider {
    public static currentPanel: ResultsPanelProvider | undefined;
    private readonly panel: vscode.WebviewPanel;
    private findings: Finding[] = [];
    private llmResults: LLMScanResult[] = [];
    private activeTab: 'findings' | 'llm' = 'findings';
    private activeTypeFilter: 'all' | 'iac' | 'vulnerability' | 'secret' | 'malware' = 'all';
    private activeSeverityFilter: 'all' | 'critical' | 'high' | 'medium' | 'low' = 'all';
    private isScanning: boolean = false;
    private scanErrors: ScanError[] = [];
    private scanSummary: ScanSummary | null = null;
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
                    case 'switchTab':
                        this.activeTab = message.tab;
                        this.updatePanel();
                        break;
                    case 'filterType':
                        this.activeTypeFilter = message.type;
                        this.updatePanel();
                        break;
                    case 'filterSeverity':
                        this.activeSeverityFilter = message.severity;
                        this.updatePanel();
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

    public addLLMResults(result: LLMScanResult): void {
        this.llmResults.push(result);

        // Also add successful attacks to findings for unified view
        for (const attackResult of result.results) {
            if (attackResult.outcome === 'Attack Succeeded') {
                this.findings.push(this.convertLLMAttack(attackResult, result));
            }
        }

        // Switch to LLM tab when adding LLM results
        this.activeTab = 'llm';
        this.updatePanel();
    }

    private convertLLMAttack(attack: LLMAttackResult, scanResult: LLMScanResult): Finding {
        return {
            id: `llm-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            ruleId: attack.objective,
            type: 'llm',
            severity: attack.severity?.toLowerCase() || 'medium',
            title: `${attack.objective} - Attack Succeeded`,
            description: attack.evaluation || 'The model was susceptible to this attack.',
            resource: `${scanResult.details.model} @ ${scanResult.details.endpoint}`,
            resolution: this.getLLMResolution(attack.objective),
            attackPrompt: attack.attackPrompt,
            modelResponse: attack.modelResponse,
            technique: attack.technique,
            modifier: attack.modifier,
            evaluation: attack.evaluation
        };
    }

    private getLLMResolution(objective: string): string {
        const resolutions: Record<string, string> = {
            'System Prompt Leakage': '1. Avoid storing sensitive information in system prompts\n2. Implement output filtering to detect and block system prompt content\n3. Use separate, non-disclosable configuration for sensitive instructions',
            'Sensitive Data Disclosure': '1. Never include PII or secrets in training data or prompts\n2. Implement output scanning for sensitive patterns (SSN, credit cards, etc.)\n3. Use data masking for any user-specific information',
            'Agent Tool Definition Leakage': '1. Keep tool definitions minimal and non-sensitive\n2. Implement guardrails to prevent tool enumeration\n3. Consider using indirect references instead of exposing tool names',
            'Malicious Code Generation': '1. Implement code output scanning for known malicious patterns\n2. Use allowlists for permitted code constructs\n3. Add safety disclaimers and refuse dangerous requests'
        };
        return resolutions[objective] || 'Review your LLM configuration and implement appropriate guardrails.';
    }

    public clear(): void {
        this.findings = [];
        this.llmResults = [];
        this.scanErrors = [];
        this.scanSummary = null;
        this.activeTypeFilter = 'all';
        this.activeSeverityFilter = 'all';
        this.updatePanel();
    }

    public setScanning(scanning: boolean): void {
        this.isScanning = scanning;
        if (scanning) {
            this.scanErrors = [];
            this.scanSummary = null;
        }
        this.updatePanel();
    }

    public addError(error: ScanError): void {
        this.scanErrors.push(error);
        this.updatePanel();
    }

    public setScanSummary(summary: ScanSummary): void {
        this.scanSummary = summary;
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

    private getSeverityCounts(findingsToCount?: Finding[]): SeverityCounts {
        const findings = findingsToCount || this.findings;
        const counts: SeverityCounts = {
            extreme: 0,
            veryHigh: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        for (const finding of findings) {
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

    private getTypeCounts(): { iac: number; vulnerability: number; secret: number; malware: number } {
        return {
            iac: this.findings.filter(f => f.type === 'iac').length,
            vulnerability: this.findings.filter(f => f.type === 'vulnerability').length,
            secret: this.findings.filter(f => f.type === 'secret').length,
            malware: this.findings.filter(f => f.type === 'malware').length
        };
    }

    private getFilteredFindings(): Finding[] {
        let filtered = this.findings;

        // Apply type filter
        if (this.activeTypeFilter !== 'all') {
            filtered = filtered.filter(f => f.type === this.activeTypeFilter);
        }

        // Apply severity filter
        if (this.activeSeverityFilter !== 'all') {
            filtered = filtered.filter(f => this.getSeverityClass(f.severity) === this.activeSeverityFilter);
        }

        return filtered;
    }

    private mapSeverityDisplay(severity: string): string {
        const s = severity.toLowerCase();
        if (s === 'extreme' || s === 'critical') return 'Critical';
        if (s === 'very_high' || s === 'very high' || s === 'veryhigh') return 'High';
        if (s === 'high') return 'Medium';
        if (s === 'medium') return 'Medium';
        return 'Low';
    }

    private getSeverityClass(severity: string): string {
        const s = severity.toLowerCase();
        if (s === 'extreme' || s === 'critical') return 'critical';
        if (s === 'very_high' || s === 'very high' || s === 'veryhigh') return 'high';
        if (s === 'high') return 'medium';
        if (s === 'medium') return 'medium';
        return 'low';
    }

    private updatePanel(): void {
        this.panel.webview.html = this.getHtmlContent();
    }

    private getHtmlContent(): string {
        const typeCounts = this.getTypeCounts();
        const filteredFindings = this.getFilteredFindings();
        const counts = this.getSeverityCounts(filteredFindings);
        const total = this.findings.length;
        const filteredTotal = filteredFindings.length;
        const hasLLMResults = this.llmResults.length > 0;
        const llmSuccessCount = this.llmResults.reduce((acc, r) => acc + r.summary.totalSuccessful, 0);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrendAI™ Security Results</title>
    <style>
        :root {
            /* Muted, professional severity palette */
            --critical-color: #c53030;
            --high-color: #c05621;
            --medium-color: #b7791f;
            --low-color: #2f855a;
            --info-color: #2b6cb0;

            /* Accent - Trend Micro red */
            --accent-color: #d1232a;
            --accent-subtle: rgba(209, 35, 42, 0.08);

            /* VS Code theme integration */
            --bg-primary: var(--vscode-editor-background);
            --bg-secondary: var(--vscode-sideBar-background, var(--vscode-editor-background));
            --bg-elevated: var(--vscode-editorWidget-background);
            --text-primary: var(--vscode-editor-foreground);
            --text-secondary: var(--vscode-descriptionForeground, rgba(255,255,255,0.7));
            --text-muted: var(--vscode-disabledForeground, rgba(255,255,255,0.5));
            --border-subtle: var(--vscode-widget-border, rgba(255,255,255,0.08));
            --border-default: var(--vscode-panel-border, rgba(255,255,255,0.12));
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            font-size: 13px;
            color: var(--text-primary);
            background: var(--bg-primary);
            padding: 16px 24px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        /* Header */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .header-logo {
            height: 20px;
            width: auto;
        }

        .header h1 {
            font-size: 16px;
            font-weight: 600;
            letter-spacing: -0.3px;
            color: var(--text-primary);
        }

        .header-meta {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 11px;
            color: var(--text-muted);
        }

        /* Tech Icons - Using local SVG files */
        .tech-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
            border-radius: 4px;
            flex-shrink: 0;
        }

        .tech-icon img {
            width: 16px;
            height: 16px;
            object-fit: contain;
        }

        /* Summary Stats */
        .summary {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
        }

        .stat-item {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 8px 12px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            min-width: 80px;
        }

        .stat-indicator {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }

        .stat-indicator.critical { background: var(--critical-color); }
        .stat-indicator.high { background: var(--high-color); }
        .stat-indicator.medium { background: var(--medium-color); }
        .stat-indicator.low { background: var(--low-color); }

        .stat-content {
            display: flex;
            flex-direction: column;
        }

        .stat-value {
            font-size: 15px;
            font-weight: 600;
            line-height: 1.2;
            color: var(--text-primary);
        }

        .stat-label {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        /* Progress Bar */
        .severity-bar {
            height: 3px;
            background: var(--border-subtle);
            border-radius: 2px;
            overflow: hidden;
            display: flex;
            margin-bottom: 16px;
        }

        .severity-bar-segment {
            height: 100%;
            transition: width 0.3s ease;
        }

        .severity-bar-segment.critical { background: var(--critical-color); }
        .severity-bar-segment.high { background: var(--high-color); }
        .severity-bar-segment.medium { background: var(--medium-color); }
        .severity-bar-segment.low { background: var(--low-color); }

        /* Filters */
        .toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .filters {
            display: flex;
            gap: 4px;
        }

        .filter-btn {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 4px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 500;
            transition: all 0.15s ease;
        }

        .filter-btn:hover {
            background: var(--bg-elevated);
            border-color: var(--border-default);
            color: var(--text-primary);
        }

        .filter-btn.active {
            background: var(--accent-subtle);
            border-color: var(--accent-color);
            color: var(--accent-color);
        }

        .view-controls {
            display: flex;
            gap: 8px;
        }

        .view-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 6px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.15s ease;
        }

        .view-btn:hover {
            background: var(--bg-elevated);
            color: var(--text-primary);
        }

        /* Section Title */
        .section-title {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.4px;
            margin-bottom: 10px;
        }

        /* Findings List */
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1px;
        }

        /* Finding Row */
        .finding-row {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            overflow: hidden;
            transition: border-color 0.15s ease;
        }

        .finding-row:hover {
            border-color: var(--border-default);
        }

        .finding-row.expanded {
            border-color: var(--accent-color);
        }

        .finding-header {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            cursor: pointer;
        }

        .severity-indicator {
            width: 3px;
            height: 24px;
            border-radius: 2px;
            flex-shrink: 0;
        }

        .severity-indicator.critical { background: var(--critical-color); }
        .severity-indicator.high { background: var(--high-color); }
        .severity-indicator.medium { background: var(--medium-color); }
        .severity-indicator.low { background: var(--low-color); }

        .finding-main {
            flex: 1;
            min-width: 0;
        }

        .finding-title {
            font-size: 12px;
            font-weight: 500;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .finding-subtitle {
            font-size: 10px;
            color: var(--text-muted);
            margin-top: 1px;
        }

        .finding-badges {
            display: flex;
            gap: 4px;
            align-items: center;
        }

        .badge {
            padding: 2px 6px;
            border-radius: 2px;
            font-size: 9px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .badge-severity {
            color: white;
        }

        .badge-severity.critical { background: var(--critical-color); }
        .badge-severity.high { background: var(--high-color); }
        .badge-severity.medium { background: var(--medium-color); }
        .badge-severity.low { background: var(--low-color); }

        .badge-type {
            background: var(--bg-primary);
            color: var(--text-secondary);
            border: 1px solid var(--border-subtle);
        }

        .badge-fix {
            background: var(--low-color);
            color: white;
        }

        .badge-nofix {
            background: var(--bg-primary);
            color: var(--text-muted);
            border: 1px solid var(--border-subtle);
        }

        .finding-location {
            font-size: 10px;
            color: var(--text-muted);
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 2px;
            transition: all 0.15s ease;
        }

        .finding-location:hover {
            background: var(--bg-primary);
            color: var(--accent-color);
        }

        .expand-icon {
            color: var(--text-muted);
            font-size: 10px;
            transition: transform 0.2s ease;
        }

        .finding-row.expanded .expand-icon {
            transform: rotate(90deg);
        }

        /* Finding Details */
        .finding-details {
            display: none;
            padding: 12px 12px 12px 24px;
            background: var(--bg-primary);
            border-top: 1px solid var(--border-subtle);
        }

        .finding-row.expanded .finding-details {
            display: block;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: 100px 1fr;
            gap: 4px 12px;
            font-size: 11px;
            margin-bottom: 12px;
        }

        .detail-label {
            color: var(--text-muted);
            font-weight: 500;
        }

        .detail-value {
            color: var(--text-primary);
        }

        .compliance-list {
            display: flex;
            gap: 3px;
            flex-wrap: wrap;
        }

        .compliance-tag {
            padding: 1px 5px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 2px;
            font-size: 9px;
            color: var(--text-secondary);
        }

        .detail-section {
            margin-top: 10px;
        }

        .detail-section-title {
            font-size: 10px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.4px;
            margin-bottom: 4px;
        }

        .detail-section p {
            font-size: 11px;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .resolution-box {
            background: var(--bg-elevated);
            border-left: 2px solid var(--accent-color);
            padding: 8px 12px;
            font-size: 11px;
            color: var(--text-secondary);
            line-height: 1.5;
            white-space: pre-wrap;
        }

        .link-btn {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-top: 8px;
            padding: 5px 10px;
            background: transparent;
            border: 1px solid var(--border-default);
            color: var(--text-secondary);
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 500;
            transition: all 0.15s ease;
        }

        .link-btn:hover {
            background: var(--bg-elevated);
            border-color: var(--accent-color);
            color: var(--accent-color);
        }

        /* File Groups */
        .file-group {
            margin-bottom: 8px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            overflow: hidden;
        }

        .file-header {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-subtle);
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .file-header:hover {
            background: var(--bg-elevated);
        }

        .file-indicator {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }

        .file-indicator.critical { background: var(--critical-color); }
        .file-indicator.high { background: var(--high-color); }
        .file-indicator.medium { background: var(--medium-color); }
        .file-indicator.low { background: var(--low-color); }

        .file-name {
            flex: 1;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-primary);
            font-family: 'SF Mono', Consolas, monospace;
        }

        .file-count {
            font-size: 10px;
            color: var(--text-muted);
        }

        .file-expand-icon {
            color: var(--text-muted);
            font-size: 11px;
            transition: transform 0.2s ease;
        }

        .file-group.collapsed .file-expand-icon {
            transform: rotate(-90deg);
        }

        .file-group.collapsed .file-findings {
            display: none;
        }

        .file-findings {
            padding: 8px;
        }

        /* Resource Groups */
        .resource-group {
            margin-bottom: 4px;
        }

        .resource-header {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 10px;
            background: var(--bg-primary);
            border: 1px solid var(--border-subtle);
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .resource-header:hover {
            border-color: var(--border-default);
        }

        .resource-indicator {
            width: 5px;
            height: 5px;
            border-radius: 50%;
        }

        .resource-indicator.critical { background: var(--critical-color); }
        .resource-indicator.high { background: var(--high-color); }
        .resource-indicator.medium { background: var(--medium-color); }
        .resource-indicator.low { background: var(--low-color); }

        .resource-name {
            flex: 1;
            font-size: 11px;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .resource-count {
            font-size: 9px;
            color: var(--text-muted);
        }

        .resource-expand-icon {
            color: var(--text-muted);
            font-size: 9px;
            transition: transform 0.2s ease;
        }

        .resource-group.collapsed .resource-expand-icon {
            transform: rotate(-90deg);
        }

        .resource-group.collapsed .resource-findings {
            display: none;
        }

        .resource-findings {
            padding: 4px 0 4px 16px;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 80px 40px;
        }

        .empty-state-icon {
            width: 48px;
            height: 48px;
            margin: 0 auto 16px;
            opacity: 0.3;
        }

        .empty-state h2 {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .empty-state p {
            font-size: 13px;
            color: var(--text-muted);
        }

        /* Loading State */
        .loading-state {
            text-align: center;
            padding: 80px 40px;
        }

        .loading-spinner {
            width: 48px;
            height: 48px;
            margin: 0 auto 20px;
            border: 3px solid var(--border-subtle);
            border-top-color: var(--accent-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loading-state h2 {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .loading-state p {
            font-size: 13px;
            color: var(--text-muted);
        }

        /* Error State */
        .error-banner {
            background: rgba(197, 48, 48, 0.1);
            border: 1px solid var(--critical-color);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 20px;
        }

        .error-banner-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }

        .error-banner-icon {
            color: var(--critical-color);
            font-size: 18px;
        }

        .error-banner-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--critical-color);
        }

        .error-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .error-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 12px;
            background: var(--bg-elevated);
            border-radius: 4px;
            margin-bottom: 6px;
            font-size: 12px;
        }

        .error-item:last-child {
            margin-bottom: 0;
        }

        .error-code {
            background: var(--critical-color);
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            flex-shrink: 0;
        }

        .error-content {
            flex: 1;
            min-width: 0;
        }

        .error-message {
            color: var(--text-primary);
            margin-bottom: 4px;
        }

        .error-details {
            color: var(--text-muted);
            font-size: 11px;
        }

        .error-file {
            color: var(--text-secondary);
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 11px;
        }

        /* Scan Summary Banner */
        .scan-summary {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 12px 16px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
        }

        .scan-summary.has-errors {
            border-color: var(--high-color);
            background: rgba(192, 86, 33, 0.05);
        }

        .scan-summary-stat {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .scan-summary-stat.success {
            color: var(--low-color);
        }

        .scan-summary-stat.failed {
            color: var(--critical-color);
        }

        .scan-summary-stat .value {
            font-weight: 600;
        }

        /* Type Tabs */
        .type-tabs {
            display: flex;
            gap: 6px;
            margin-bottom: 12px;
        }

        .type-tab {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 500;
            color: var(--text-secondary);
            transition: all 0.15s ease;
        }

        .type-tab:hover {
            border-color: var(--border-default);
            color: var(--text-primary);
        }

        .type-tab.active {
            background: var(--accent-subtle);
            border-color: var(--accent-color);
            color: var(--accent-color);
        }

        .type-tab .count {
            padding: 1px 6px;
            background: var(--bg-primary);
            border-radius: 8px;
            font-size: 10px;
            font-weight: 600;
        }

        .type-tab.active .count {
            background: rgba(209, 35, 42, 0.15);
        }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 0;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .tab {
            padding: 8px 16px;
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            transition: all 0.15s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .tab:hover {
            color: var(--text-primary);
        }

        .tab.active {
            color: var(--text-primary);
            border-bottom-color: var(--accent-color);
        }

        .tab .badge {
            background: var(--bg-elevated);
            color: var(--text-muted);
            padding: 1px 6px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 600;
        }

        .tab.active .badge {
            background: var(--accent-subtle);
            color: var(--accent-color);
        }

        .tab .badge.warning {
            background: rgba(197, 48, 48, 0.15);
            color: var(--critical-color);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* LLM Scan Card */
        .llm-scan-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .llm-scan-header {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .llm-icon {
            width: 40px;
            height: 40px;
            background: var(--accent-subtle);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }

        .llm-scan-header .info {
            flex: 1;
        }

        .llm-scan-header .model-name {
            font-size: 15px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .llm-scan-header .endpoint {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 2px;
        }

        .llm-scan-header .scan-time {
            font-size: 11px;
            color: var(--text-muted);
        }

        .llm-summary {
            display: flex;
            gap: 1px;
            background: var(--border-subtle);
        }

        .llm-stat {
            flex: 1;
            text-align: center;
            padding: 20px;
            background: var(--bg-elevated);
        }

        .llm-stat .value {
            font-size: 28px;
            font-weight: 600;
            line-height: 1;
            color: var(--text-primary);
        }

        .llm-stat .label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 6px;
        }

        .llm-stat.success .value { color: var(--low-color); }
        .llm-stat.failed .value { color: var(--critical-color); }
        .llm-stat.rate .value { color: var(--accent-color); }

        /* Objective Table */
        .objective-table {
            width: 100%;
            border-collapse: collapse;
        }

        .objective-table th,
        .objective-table td {
            padding: 12px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border-subtle);
        }

        .objective-table th {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: var(--bg-primary);
        }

        .objective-table td {
            font-size: 13px;
            color: var(--text-primary);
        }

        .objective-table tr:hover td {
            background: var(--bg-primary);
        }

        .success-rate {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-weight: 600;
            font-size: 11px;
        }

        .success-rate.high { background: rgba(197, 48, 48, 0.15); color: var(--critical-color); }
        .success-rate.medium { background: rgba(192, 86, 33, 0.15); color: var(--high-color); }
        .success-rate.low { background: rgba(47, 133, 90, 0.15); color: var(--low-color); }

        /* Attack Cards */
        .attack-details {
            margin-top: 24px;
        }

        .attack-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            margin-bottom: 8px;
            overflow: hidden;
        }

        .attack-card-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            cursor: pointer;
            transition: background 0.15s ease;
        }

        .attack-card-header:hover {
            background: var(--bg-primary);
        }

        .attack-outcome {
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .attack-outcome.succeeded { background: rgba(197, 48, 48, 0.15); color: var(--critical-color); }
        .attack-outcome.failed { background: rgba(47, 133, 90, 0.15); color: var(--low-color); }

        .attack-card-body {
            display: none;
            padding: 16px;
            border-top: 1px solid var(--border-subtle);
            background: var(--bg-primary);
        }

        .attack-card.expanded .attack-card-body {
            display: block;
        }

        .chat-message {
            margin-bottom: 12px;
            padding: 12px 16px;
            border-radius: 6px;
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 12px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .chat-message.user {
            background: var(--bg-elevated);
            border-left: 2px solid var(--accent-color);
        }

        .chat-message.assistant {
            background: var(--bg-elevated);
            border-left: 2px solid var(--info-color);
        }

        .chat-label {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-weight: 600;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            color: var(--text-muted);
        }

        .evaluation-box {
            background: var(--bg-elevated);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 12px;
            border-left: 2px solid var(--medium-color);
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <svg class="header-logo" viewBox="0 0 120 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M31.8187 3.58109V6.73022H36.9232V20.3431H40.3276V6.73022H45.454V3.58109H31.8187Z" fill="var(--text-primary)"/>
                <path d="M51.7366 7.66468C50.1406 7.56835 48.5064 7.87325 47.5768 9.35806L47.3655 7.86637H44.3877V20.3431H47.6964V14.4961C47.6964 13.6594 47.8419 12.9725 48.1329 12.4353C48.9363 10.9574 50.5468 10.8286 52.1153 10.8737V7.67667C52.0355 7.67667 51.91 7.67268 51.7366 7.66468Z" fill="var(--text-primary)"/>
                <path d="M64.2797 11.4289C63.7949 9.94462 62.7843 8.75345 61.3477 8.12598C59.6901 7.3796 57.0899 7.52575 55.5814 8.48143C53.5959 9.68012 52.678 11.7751 52.6873 14.1646C52.6845 16.5059 53.5418 18.5926 55.5236 19.728C57.0535 20.6324 59.5544 20.7456 61.3357 20.0954C62.9796 19.5092 64.1296 18.2636 64.5029 16.485H61.2421C60.7287 17.8361 58.3795 17.9552 57.3075 17.3477C56.4864 16.8937 56.0679 16.027 55.9721 15.1112H64.5029C64.6035 14.6887 64.6182 14.2922 64.6205 13.8551C64.6364 12.9884 64.5228 12.1797 64.2797 11.4289ZM56.0438 12.7907C56.1486 11.3249 57.2451 10.312 58.7845 10.3525C60.3126 10.3041 61.4035 11.3251 61.4553 12.7907H56.0438Z" fill="var(--text-primary)"/>
                <path d="M77.1038 10.5302C76.8128 9.6536 76.3324 8.95468 75.6627 8.43349C73.959 7.14822 70.4768 7.43118 69.0334 9.31013L68.868 7.86637H65.7726V20.3431H69.0813V14.1866C69.0813 13.5396 69.1829 12.9485 69.3882 12.4113C69.5935 11.8762 69.9084 11.4488 70.333 11.1333C70.9894 10.6028 72.3788 10.484 73.0995 10.9436C73.3985 11.1333 73.6297 11.3869 73.7951 11.7024C74.1401 12.3444 74.2273 13.1522 74.2336 13.8791V20.3431H77.5423V13.4537C77.5423 12.3814 77.3948 11.4049 77.1038 10.5302Z" fill="var(--text-primary)"/>
                <path d="M87.9567 3.58101V9.02659C87.1174 8.04276 85.7433 7.6679 84.4826 7.65267C80.6449 7.57899 78.5861 10.4676 78.6227 14.0928C78.5908 17.531 80.4848 20.5917 84.2235 20.5088C85.6464 20.5056 87.1035 20.0839 88.0045 18.9472L88.0504 20.3431H91.2654V3.58101H87.9567ZM87.6258 15.7502C87.1344 16.8735 86.2001 17.546 84.8852 17.5254C83.4892 17.5649 82.4034 16.7503 82.0848 15.4306C81.8429 14.4919 81.8889 13.374 82.2024 12.4713C82.6172 11.3056 83.5639 10.6659 84.8852 10.684C86.2024 10.6703 87.1491 11.2403 87.6378 12.3754C88.062 13.3829 88.0687 14.7348 87.6258 15.7502Z" fill="var(--text-primary)"/>
                <path d="M110.426 3.58101V20.3431H113.805V3.58101H110.426Z" fill="var(--text-primary)"/>
                <path d="M105.601 20.3431H109.241L102.789 3.57901H99.0095L92.4858 20.3431H96.1254L97.3508 16.9553C99.6306 17.5055 102.099 17.5064 104.379 16.9529L105.601 20.3431ZM98.3873 14.0518L98.3877 14.0508L100.899 7.17945L103.363 14.0475C101.539 14.3618 100.453 14.4009 98.3873 14.0518Z" fill="var(--text-primary)"/>
                <path d="M116.575 3.78987H115.901V3.58101H117.474V3.78987H116.8V5.58377H116.575V3.78987Z" fill="var(--text-primary)"/>
                <path d="M117.887 3.58101H118.115L118.843 4.67385L119.571 3.58101H119.8V5.58377H119.574V3.96147L118.846 5.03442H118.835L118.106 3.9644V5.58377H117.887V3.58101Z" fill="var(--text-primary)"/>
                <path d="M6.96222 9.35451C8.07448 10.4895 9.15806 11.8946 9.40997 13.3781C9.86335 10.8353 13.2843 7.3741 15.8378 6.93567C13.301 6.52454 9.81308 3.03499 9.41016 0.487976C8.95338 3.00104 5.5085 6.49335 2.9821 6.93194C4.4545 7.18582 5.83181 8.25001 6.96222 9.35451Z" fill="#D71920"/>
                <path d="M27.213 2.07553C24.5879 -1.06058 19.7076 -0.10279 15.9381 1.43011C21.9204 -0.460249 27.4062 2.02712 24.5436 9.13743C23.1255 12.6331 19.5587 16.2087 16.1405 18.2299C14.3356 19.3968 12.4048 20.3795 10.3009 20.6737C7.06406 21.1179 5.12422 19.4468 5.94753 16.1075C6.15515 15.2921 6.5331 14.4689 6.90833 13.668C6.2906 12.2019 4.96151 10.7021 3.53516 10.2853C2.76628 11.4421 2.20686 12.4894 1.63765 14.1086C0.349495 17.5885 0.770259 22.6983 5.17193 23.8039C13.2271 25.4088 24.1238 16.8467 27.2253 9.71133C28.5528 6.70416 28.6477 3.92461 27.213 2.07553Z" fill="#D71920"/>
            </svg>
            <h1>Security Report</h1>
        </div>
        <div class="header-meta">
            <span>${total} issues</span>
        </div>
    </div>

    ${hasLLMResults ? `
    <div class="tabs">
        <button class="tab ${this.activeTab === 'findings' ? 'active' : ''}" onclick="switchTab('findings')">
            Findings <span class="badge">${total}</span>
        </button>
        <button class="tab ${this.activeTab === 'llm' ? 'active' : ''}" onclick="switchTab('llm')">
            LLM Security <span class="badge ${llmSuccessCount > 0 ? 'warning' : ''}">${llmSuccessCount}</span>
        </button>
    </div>
    ` : ''}

    <div class="tab-content ${this.activeTab === 'findings' || !hasLLMResults ? 'active' : ''}" id="findings-tab">
    ${this.isScanning ? this.getLoadingState() : total === 0 && this.scanErrors.length === 0 && !hasLLMResults ? this.getEmptyState() : `
    <!-- Error Banner -->
    ${this.getErrorBannerHtml()}

    <!-- Scan Summary -->
    ${this.getScanSummaryHtml()}

    <!-- Overview Summary -->
    <div class="summary">
        <div class="stat-item">
            <div class="stat-indicator critical"></div>
            <div class="stat-content">
                <div class="stat-value">${this.getSeverityCounts().extreme}</div>
                <div class="stat-label">Critical</div>
            </div>
        </div>
        <div class="stat-item">
            <div class="stat-indicator high"></div>
            <div class="stat-content">
                <div class="stat-value">${this.getSeverityCounts().veryHigh}</div>
                <div class="stat-label">High</div>
            </div>
        </div>
        <div class="stat-item">
            <div class="stat-indicator medium"></div>
            <div class="stat-content">
                <div class="stat-value">${this.getSeverityCounts().high + this.getSeverityCounts().medium}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>
        <div class="stat-item">
            <div class="stat-indicator low"></div>
            <div class="stat-content">
                <div class="stat-value">${this.getSeverityCounts().low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
    </div>

    <div class="severity-bar">
        ${this.getBarSegments(this.getSeverityCounts(), total)}
    </div>

    <!-- Type Filter Tabs -->
    <div class="type-tabs">
        <button class="type-tab ${this.activeTypeFilter === 'all' ? 'active' : ''}" onclick="filterType('all')">
            All <span class="count">${total}</span>
        </button>
        <button class="type-tab ${this.activeTypeFilter === 'iac' ? 'active' : ''}" onclick="filterType('iac')">
            IaC <span class="count">${typeCounts.iac}</span>
        </button>
        <button class="type-tab ${this.activeTypeFilter === 'vulnerability' ? 'active' : ''}" onclick="filterType('vulnerability')">
            Vulnerabilities <span class="count">${typeCounts.vulnerability}</span>
        </button>
        <button class="type-tab ${this.activeTypeFilter === 'secret' ? 'active' : ''}" onclick="filterType('secret')">
            Secrets <span class="count">${typeCounts.secret}</span>
        </button>
        ${typeCounts.malware > 0 ? `<button class="type-tab ${this.activeTypeFilter === 'malware' ? 'active' : ''}" onclick="filterType('malware')">
            Malware <span class="count">${typeCounts.malware}</span>
        </button>` : ''}
    </div>

    <!-- Severity Filter -->
    <div class="toolbar">
        <div class="filters">
            <span style="font-size: 11px; color: var(--text-muted); margin-right: 8px; text-transform: uppercase; letter-spacing: 0.5px;">Severity:</span>
            <button class="filter-btn ${this.activeSeverityFilter === 'all' ? 'active' : ''}" onclick="filterSeverity('all')">All</button>
            <button class="filter-btn ${this.activeSeverityFilter === 'critical' ? 'active' : ''}" onclick="filterSeverity('critical')">Critical</button>
            <button class="filter-btn ${this.activeSeverityFilter === 'high' ? 'active' : ''}" onclick="filterSeverity('high')">High</button>
            <button class="filter-btn ${this.activeSeverityFilter === 'medium' ? 'active' : ''}" onclick="filterSeverity('medium')">Medium</button>
            <button class="filter-btn ${this.activeSeverityFilter === 'low' ? 'active' : ''}" onclick="filterSeverity('low')">Low</button>
        </div>
        <div class="view-controls">
            <button class="view-btn" onclick="expandAll()">Expand All</button>
            <button class="view-btn" onclick="collapseAll()">Collapse All</button>
        </div>
    </div>

    <div class="section-title">${filteredTotal} Findings${this.activeTypeFilter !== 'all' || this.activeSeverityFilter !== 'all' ? ' (filtered)' : ''}</div>

    <div class="findings-list">
        ${this.getFindingsHtml(filteredFindings)}
    </div>
    `}
    </div>

    ${hasLLMResults ? `
    <div class="tab-content ${this.activeTab === 'llm' ? 'active' : ''}" id="llm-tab">
        ${this.getLLMResultsHtml()}
    </div>
    ` : ''}

    <script>
        const vscode = acquireVsCodeApi();

        function switchTab(tab) {
            vscode.postMessage({ command: 'switchTab', tab });
        }

        function toggleFinding(id) {
            const card = document.getElementById('finding-' + id);
            card.classList.toggle('expanded');
        }

        function toggleAttack(id) {
            const card = document.getElementById('attack-' + id);
            card.classList.toggle('expanded');
        }

        function toggleFile(file) {
            const groups = document.querySelectorAll('.file-group');
            groups.forEach(group => {
                if (group.dataset.file === file) {
                    group.classList.toggle('collapsed');
                }
            });
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

        function filterType(type) {
            vscode.postMessage({ command: 'filterType', type });
        }

        function filterSeverity(severity) {
            vscode.postMessage({ command: 'filterSeverity', severity });
        }

        function expandAll() {
            document.querySelectorAll('.file-group, .resource-group').forEach(g => g.classList.remove('collapsed'));
        }

        function collapseAll() {
            document.querySelectorAll('.file-group, .resource-group').forEach(g => g.classList.add('collapsed'));
        }
    </script>
</body>
</html>`;
    }

    private getLoadingState(): string {
        return `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <h2>Scanning in Progress</h2>
            <p>Analyzing for IaC misconfigurations, vulnerabilities, and secrets...</p>
        </div>`;
    }

    private getEmptyState(): string {
        return `
        <div class="empty-state">
            <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M9 12l2 2 4-4"/>
                <circle cx="12" cy="12" r="10"/>
            </svg>
            <h2>No Issues Found</h2>
            <p>Run a security scan to see findings here.</p>
        </div>`;
    }

    private getErrorBannerHtml(): string {
        if (this.scanErrors.length === 0) {
            return '';
        }

        const errorItems = this.scanErrors.map(error => `
            <li class="error-item">
                <span class="error-code">${this.escapeHtml(error.code)}</span>
                <div class="error-content">
                    <div class="error-message">${this.escapeHtml(error.message)}</div>
                    ${error.details ? `<div class="error-details">${this.escapeHtml(error.details)}</div>` : ''}
                    ${error.file ? `<div class="error-file">${this.escapeHtml(error.file)}</div>` : ''}
                </div>
            </li>
        `).join('');

        return `
        <div class="error-banner">
            <div class="error-banner-header">
                <span class="error-banner-icon">⚠</span>
                <span class="error-banner-title">${this.scanErrors.length} Error${this.scanErrors.length > 1 ? 's' : ''} During Scan</span>
            </div>
            <ul class="error-list">
                ${errorItems}
            </ul>
        </div>`;
    }

    private getScanSummaryHtml(): string {
        if (!this.scanSummary) {
            return '';
        }

        const { totalFiles, successfulScans, failedScans } = this.scanSummary;
        const hasErrors = failedScans > 0;

        return `
        <div class="scan-summary ${hasErrors ? 'has-errors' : ''}">
            <span class="scan-summary-stat">
                Scanned <span class="value">${totalFiles}</span> file${totalFiles !== 1 ? 's' : ''}
            </span>
            <span class="scan-summary-stat success">
                <span class="value">${successfulScans}</span> successful
            </span>
            ${hasErrors ? `
            <span class="scan-summary-stat failed">
                <span class="value">${failedScans}</span> failed
            </span>
            ` : ''}
        </div>`;
    }

    private getBarSegments(counts: SeverityCounts, total: number): string {
        if (total === 0) return '';

        const segments: string[] = [];
        const severityMap: { key: keyof SeverityCounts; cssClass: string }[] = [
            { key: 'extreme', cssClass: 'critical' },
            { key: 'veryHigh', cssClass: 'high' },
            { key: 'high', cssClass: 'medium' },
            { key: 'medium', cssClass: 'medium' },
            { key: 'low', cssClass: 'low' }
        ];

        for (const { key, cssClass } of severityMap) {
            const count = counts[key];
            if (count > 0) {
                const percent = (count / total) * 100;
                segments.push(`<div class="severity-bar-segment ${cssClass}" style="width: ${percent}%"></div>`);
            }
        }

        return segments.join('');
    }

    private getFindingsHtml(findingsToRender?: Finding[]): string {
        const findings = findingsToRender || this.findings;

        if (findings.length === 0) {
            return `<div class="empty-state" style="padding: 40px 20px;">
                <p style="color: var(--text-muted);">No findings match the current filters.</p>
            </div>`;
        }

        // Group findings by file first, then by resource
        const byFile = new Map<string, Finding[]>();

        for (const finding of findings) {
            const file = finding.file || 'Unknown';
            if (!byFile.has(file)) {
                byFile.set(file, []);
            }
            byFile.get(file)!.push(finding);
        }

        // Sort files by highest severity finding
        const sortedFiles = Array.from(byFile.entries()).sort((a, b) => {
            const aMax = Math.max(...a[1].map(f => this.severityToNumber(f.severity)));
            const bMax = Math.max(...b[1].map(f => this.severityToNumber(f.severity)));
            return bMax - aMax;
        });

        let html = '';
        let findingIndex = 0;

        for (const [file, fileFindings] of sortedFiles) {
            // Get highest severity for file header
            const fileHighestSev = fileFindings.reduce((max, f) =>
                this.severityToNumber(f.severity) > this.severityToNumber(max.severity) ? f : max
            );
            const fileSevClass = this.getSeverityClass(fileHighestSev.severity);
            const fileName = this.getShortPath(file);

            // Group this file's findings by resource
            const byResource = new Map<string, Finding[]>();
            for (const finding of fileFindings) {
                const resource = finding.resource || 'General';
                if (!byResource.has(resource)) {
                    byResource.set(resource, []);
                }
                byResource.get(resource)!.push(finding);
            }

            // Sort resources by severity
            const sortedResources = Array.from(byResource.entries()).sort((a, b) => {
                const aMax = Math.max(...a[1].map(f => this.severityToNumber(f.severity)));
                const bMax = Math.max(...b[1].map(f => this.severityToNumber(f.severity)));
                return bMax - aMax;
            });

            const fileIcon = this.getFileIcon(file);
            html += `
            <div class="file-group" data-file="${this.escapeHtml(file)}">
                <div class="file-header" onclick="toggleFile('${this.escapeHtml(file).replace(/'/g, "\\'")}')">
                    <span class="file-indicator ${fileSevClass}"></span>
                    ${fileIcon}
                    <span class="file-name">${this.escapeHtml(fileName)}</span>
                    <span class="file-count">${fileFindings.length}</span>
                    <span class="file-expand-icon">›</span>
                </div>
                <div class="file-findings">`;

            for (const [resource, findings] of sortedResources) {
                // Get highest severity for resource header color
                const highestSev = findings.reduce((max, f) =>
                    this.severityToNumber(f.severity) > this.severityToNumber(max.severity) ? f : max
                );
                const resourceSevClass = this.getSeverityClass(highestSev.severity);

                html += `
                <div class="resource-group" data-resource="${this.escapeHtml(resource)}">
                    <div class="resource-header" onclick="event.stopPropagation(); toggleResource('${this.escapeHtml(resource).replace(/'/g, "\\'")}')">
                        <span class="resource-indicator ${resourceSevClass}"></span>
                        <span class="resource-name">${this.escapeHtml(resource)}</span>
                        <span class="resource-count">${findings.length}</span>
                        <span class="resource-expand-icon">›</span>
                    </div>
                    <div class="resource-findings">`;

            for (const finding of findings) {
                const sevClass = this.getSeverityClass(finding.severity);
                const sevDisplay = this.mapSeverityDisplay(finding.severity);

                const fixBadgeHtml = finding.type === 'vulnerability'
                    ? (finding.fixAvailable
                        ? `<span class="badge badge-fix">Fix Available</span>`
                        : `<span class="badge badge-nofix">No Fix</span>`)
                    : '';

                const techIcon = this.getTechIcon(finding);
                html += `
                    <div class="finding-row" id="finding-${findingIndex}" data-severity="${sevClass}">
                        <div class="finding-header" onclick="toggleFinding(${findingIndex})">
                            <div class="severity-indicator ${sevClass}"></div>
                            ${techIcon}
                            <div class="finding-main">
                                <div class="finding-title">${this.escapeHtml(finding.title)}</div>
                                <div class="finding-subtitle">${this.escapeHtml(finding.ruleId)}${finding.service ? ` · ${finding.service}` : ''}</div>
                            </div>
                            <div class="finding-badges">
                                <span class="badge badge-severity ${sevClass}">${sevDisplay}</span>
                                <span class="badge badge-type">${finding.type}</span>
                                ${fixBadgeHtml}
                            </div>
                            ${finding.file ? `<span class="finding-location" onclick="event.stopPropagation(); openFile('${this.escapeHtml(finding.file)}', ${finding.line || 1})">${this.getShortPath(finding.file)}${finding.line ? ':' + finding.line : ''}</span>` : ''}
                            <span class="expand-icon">›</span>
                        </div>
                        <div class="finding-details">
                            <div class="detail-grid">
                                <span class="detail-label">Rule ID</span>
                                <span class="detail-value">${this.escapeHtml(finding.ruleId)}</span>
                                ${finding.service ? `<span class="detail-label">Service</span><span class="detail-value">${this.escapeHtml(finding.service)}</span>` : ''}
                                ${finding.provider ? `<span class="detail-label">Provider</span><span class="detail-value">${this.escapeHtml(finding.provider.toUpperCase())}</span>` : ''}
                                ${finding.type === 'vulnerability' && finding.installedVersion ? `<span class="detail-label">Version</span><span class="detail-value">${this.escapeHtml(finding.installedVersion)}${finding.fixAvailable ? ' → ' + this.escapeHtml(finding.fixVersion || '') : ''}</span>` : ''}
                            </div>
                            ${finding.complianceStandards && finding.complianceStandards.length > 0 ? `
                            <div class="compliance-list">
                                ${finding.complianceStandards.map(c => `<span class="compliance-tag">${this.escapeHtml(c.id)}</span>`).join('')}
                            </div>
                            ` : ''}
                            <div class="detail-section">
                                <div class="detail-section-title">Description</div>
                                <p>${this.escapeHtml(finding.description)}</p>
                            </div>
                            <div class="detail-section">
                                <div class="detail-section-title">Resolution</div>
                                <div class="resolution-box">${this.escapeHtml(finding.resolution || 'No resolution available.')}</div>
                            </div>
                            ${finding.link ? `<button class="link-btn" onclick="openLink('${this.escapeHtml(finding.link)}')">View Documentation</button>` : ''}
                        </div>
                    </div>`;
                    findingIndex++;
                }

                html += `
                    </div>
                </div>`;
            }

            html += `
                </div>
            </div>`;
        }

        return html;
    }

    private getLLMResultsHtml(): string {
        let html = '';
        let attackIndex = 0;

        for (const result of this.llmResults) {
            const totalTests = result.summary.totalSuccessful + result.summary.totalFailed;
            const successRate = totalTests > 0 ? Math.round((result.summary.totalSuccessful / totalTests) * 100) : 0;

            html += `
            <div class="llm-scan-card">
                <div class="llm-scan-header">
                    <div class="llm-icon"><img src="${this.getIconUri('ai-svgrepo-com.svg')}" alt="AI" style="width: 24px; height: 24px;"></div>
                    <div class="info">
                        <div class="model-name">${this.escapeHtml(result.details.model)}</div>
                        <div class="endpoint">${this.escapeHtml(result.details.endpoint)}</div>
                    </div>
                    <div class="scan-time">${this.escapeHtml(result.details.scanTime)}</div>
                </div>

                <div class="llm-summary">
                    <div class="llm-stat rate">
                        <div class="value">${successRate}%</div>
                        <div class="label">Success Rate</div>
                    </div>
                    <div class="llm-stat failed">
                        <div class="value">${result.summary.totalSuccessful}</div>
                        <div class="label">Succeeded</div>
                    </div>
                    <div class="llm-stat success">
                        <div class="value">${result.summary.totalFailed}</div>
                        <div class="label">Blocked</div>
                    </div>
                    <div class="llm-stat">
                        <div class="value">${totalTests}</div>
                        <div class="label">Total</div>
                    </div>
                </div>

                <div class="section-title" style="padding: 16px 20px; margin: 0;">Results by Objective</div>
                <table class="objective-table">
                    <thead>
                        <tr>
                            <th>Attack Objective</th>
                            <th>Succeeded</th>
                            <th>Blocked</th>
                            <th>Success Rate</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${Object.entries(result.summary.byObjective).map(([objective, stats]) => {
                            const objTotal = stats.successful + stats.failed;
                            const objRate = objTotal > 0 ? Math.round((stats.successful / objTotal) * 100) : 0;
                            const objRateClass = objRate >= 50 ? 'high' : objRate >= 20 ? 'medium' : 'low';
                            return `
                            <tr>
                                <td>${this.escapeHtml(objective)}</td>
                                <td>${stats.successful}</td>
                                <td>${stats.failed}</td>
                                <td><span class="success-rate ${objRateClass}">${objRate}%</span></td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            </div>

            <div class="attack-details">
                <div class="section-title">Attack Details</div>
                ${result.results.map(attack => {
                    const isSuccess = attack.outcome === 'Attack Succeeded';
                    const outcomeClass = isSuccess ? 'succeeded' : 'failed';
                    const cardId = attackIndex++;

                    return `
                    <div class="attack-card ${isSuccess ? 'expanded' : ''}" id="attack-${cardId}">
                        <div class="attack-card-header" onclick="toggleAttack(${cardId})">
                            <span class="attack-outcome ${outcomeClass}">${isSuccess ? 'Succeeded' : 'Blocked'}</span>
                            <span class="finding-title">${this.escapeHtml(attack.objective)}</span>
                            ${attack.technique !== 'None' ? `<span class="badge badge-type">${this.escapeHtml(attack.technique)}</span>` : ''}
                            <span class="expand-icon">›</span>
                        </div>
                        <div class="attack-card-body">
                            <div class="chat-message user">
                                <div class="chat-label">Attack Prompt</div>
                                ${this.escapeHtml(attack.attackPrompt || 'No prompt recorded')}
                            </div>
                            <div class="chat-message assistant">
                                <div class="chat-label">Model Response</div>
                                ${this.escapeHtml(attack.modelResponse || 'No response recorded')}
                            </div>
                            ${attack.evaluation ? `
                            <div class="evaluation-box">
                                <div class="chat-label">Evaluation</div>
                                ${this.escapeHtml(attack.evaluation)}
                            </div>
                            ` : ''}
                        </div>
                    </div>`;
                }).join('')}
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

    private getIconUri(iconName: string): string {
        const iconPath = vscode.Uri.joinPath(this.extensionUri, 'resources', 'icons', iconName);
        return this.panel.webview.asWebviewUri(iconPath).toString();
    }

    private getFileIcon(filePath: string): string {
        const file = filePath.toLowerCase();

        if (file.includes('dockerfile') || file.endsWith('.dockerfile')) {
            return `<span class="tech-icon" title="Docker"><img src="${this.getIconUri('docker2-svgrepo-com.svg')}" alt="Docker"></span>`;
        }
        if (file.endsWith('.tf') || file.includes('terraform')) {
            return `<span class="tech-icon" title="Terraform"><img src="${this.getIconUri('terraform-svgrepo-com.svg')}" alt="Terraform"></span>`;
        }
        if (file.endsWith('.py') || file.includes('requirements.txt') || file.includes('pyproject.toml') || file.includes('pipfile')) {
            return `<span class="tech-icon" title="Python"><img src="${this.getIconUri('python-svgrepo-com.svg')}" alt="Python"></span>`;
        }
        if (file.endsWith('.go') || file.includes('go.mod') || file.includes('go.sum')) {
            return `<span class="tech-icon" title="Go"><img src="${this.getIconUri('go-svgrepo-com.svg')}" alt="Go"></span>`;
        }
        if (file.endsWith('.rb') || file.includes('gemfile') || file.includes('.gemspec')) {
            return `<span class="tech-icon" title="Ruby"><img src="${this.getIconUri('ruby-svgrepo-com.svg')}" alt="Ruby"></span>`;
        }
        if (file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs') || file.endsWith('.ts') || file.endsWith('.tsx') || file.includes('package.json') || file.includes('package-lock.json') || file.includes('yarn.lock')) {
            return `<span class="tech-icon" title="Node.js"><img src="${this.getIconUri('nodejs-svgrepo-com.svg')}" alt="Node.js"></span>`;
        }
        if (file.endsWith('.java') || file.includes('pom.xml') || file.includes('build.gradle')) {
            return `<span class="tech-icon" title="Java"><img src="${this.getIconUri('java-svgrepo-com.svg')}" alt="Java"></span>`;
        }
        if (file.includes('aws') || file.includes('cloudformation') || file.includes('sam')) {
            return `<span class="tech-icon" title="AWS"><img src="${this.getIconUri('aws-svgrepo-com.svg')}" alt="AWS"></span>`;
        }
        if (file.includes('azure') || file.includes('arm-template')) {
            return `<span class="tech-icon" title="Azure"><img src="${this.getIconUri('azure-svgrepo-com.svg')}" alt="Azure"></span>`;
        }
        if (file.includes('gcp') || file.includes('google') || file.includes('gcloud')) {
            return `<span class="tech-icon" title="GCP"><img src="${this.getIconUri('gcp-svgrepo-com.svg')}" alt="GCP"></span>`;
        }

        return '';
    }

    private getTechIcon(finding: Finding): string {
        const file = (finding.file || '').toLowerCase();
        const provider = (finding.provider || '').toLowerCase();
        const type = finding.type;
        const resource = (finding.resource || '').toLowerCase();

        // Cloud providers
        if (provider === 'aws' || resource.includes('aws') || file.includes('aws') || file.includes('cloudformation')) {
            return `<span class="tech-icon" title="AWS"><img src="${this.getIconUri('aws-svgrepo-com.svg')}" alt="AWS"></span>`;
        }
        if (provider === 'azure' || resource.includes('azure') || file.includes('azure')) {
            return `<span class="tech-icon" title="Azure"><img src="${this.getIconUri('azure-svgrepo-com.svg')}" alt="Azure"></span>`;
        }
        if (provider === 'gcp' || provider === 'google' || resource.includes('gcp') || resource.includes('google')) {
            return `<span class="tech-icon" title="GCP"><img src="${this.getIconUri('gcp-svgrepo-com.svg')}" alt="GCP"></span>`;
        }

        // Container/orchestration
        if (file.includes('dockerfile') || resource.includes('docker') || file.endsWith('.dockerfile')) {
            return `<span class="tech-icon" title="Docker"><img src="${this.getIconUri('docker2-svgrepo-com.svg')}" alt="Docker"></span>`;
        }

        // IaC
        if (file.endsWith('.tf') || file.includes('terraform')) {
            return `<span class="tech-icon" title="Terraform"><img src="${this.getIconUri('terraform-svgrepo-com.svg')}" alt="Terraform"></span>`;
        }

        // Languages
        if (file.endsWith('.py') || file.includes('requirements.txt') || file.includes('pyproject.toml')) {
            return `<span class="tech-icon" title="Python"><img src="${this.getIconUri('python-svgrepo-com.svg')}" alt="Python"></span>`;
        }
        if (file.endsWith('.go') || file.includes('go.mod') || file.includes('go.sum')) {
            return `<span class="tech-icon" title="Go"><img src="${this.getIconUri('go-svgrepo-com.svg')}" alt="Go"></span>`;
        }
        if (file.endsWith('.rb') || file.includes('gemfile')) {
            return `<span class="tech-icon" title="Ruby"><img src="${this.getIconUri('ruby-svgrepo-com.svg')}" alt="Ruby"></span>`;
        }
        if (file.endsWith('.js') || file.endsWith('.ts') || file.includes('package.json') || file.includes('node_modules')) {
            return `<span class="tech-icon" title="Node.js"><img src="${this.getIconUri('nodejs-svgrepo-com.svg')}" alt="Node.js"></span>`;
        }
        if (file.endsWith('.java') || file.includes('pom.xml') || file.includes('build.gradle')) {
            return `<span class="tech-icon" title="Java"><img src="${this.getIconUri('java-svgrepo-com.svg')}" alt="Java"></span>`;
        }

        // AI/LLM
        if (type === 'llm') {
            return `<span class="tech-icon" title="AI/LLM"><img src="${this.getIconUri('ai-svgrepo-com.svg')}" alt="AI"></span>`;
        }

        return '';
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
