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
            padding: 24px 32px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        /* Header */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 32px;
        }

        .header h1 {
            font-size: 18px;
            font-weight: 600;
            letter-spacing: -0.3px;
            color: var(--text-primary);
        }

        .header-meta {
            display: flex;
            align-items: center;
            gap: 16px;
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Summary Stats */
        .summary {
            display: flex;
            gap: 12px;
            margin-bottom: 28px;
        }

        .stat-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px 16px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            min-width: 100px;
        }

        .stat-indicator {
            width: 8px;
            height: 8px;
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
            font-size: 18px;
            font-weight: 600;
            line-height: 1.2;
            color: var(--text-primary);
        }

        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Progress Bar */
        .severity-bar {
            height: 4px;
            background: var(--border-subtle);
            border-radius: 2px;
            overflow: hidden;
            display: flex;
            margin-bottom: 28px;
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
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .filters {
            display: flex;
            gap: 6px;
        }

        .filter-btn {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
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
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 16px;
        }

        /* Findings List */
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        /* Finding Row */
        .finding-row {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
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
            gap: 12px;
            padding: 12px 16px;
            cursor: pointer;
        }

        .severity-indicator {
            width: 3px;
            height: 32px;
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
            font-size: 13px;
            font-weight: 500;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .finding-subtitle {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 2px;
        }

        .finding-badges {
            display: flex;
            gap: 6px;
            align-items: center;
        }

        .badge {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 10px;
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
            font-size: 11px;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 3px;
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
            padding: 16px 16px 16px 32px;
            background: var(--bg-primary);
            border-top: 1px solid var(--border-subtle);
        }

        .finding-row.expanded .finding-details {
            display: block;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 8px 16px;
            font-size: 12px;
            margin-bottom: 16px;
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
            gap: 4px;
            flex-wrap: wrap;
        }

        .compliance-tag {
            padding: 2px 6px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 3px;
            font-size: 10px;
            color: var(--text-secondary);
        }

        .detail-section {
            margin-top: 16px;
        }

        .detail-section-title {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .detail-section p {
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .resolution-box {
            background: var(--bg-elevated);
            border-left: 2px solid var(--accent-color);
            padding: 12px 16px;
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.6;
            white-space: pre-wrap;
        }

        .link-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-top: 12px;
            padding: 8px 14px;
            background: transparent;
            border: 1px solid var(--border-default);
            color: var(--text-secondary);
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
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
            margin-bottom: 16px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            overflow: hidden;
        }

        .file-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-subtle);
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .file-header:hover {
            background: var(--bg-elevated);
        }

        .file-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .file-indicator.critical { background: var(--critical-color); }
        .file-indicator.high { background: var(--high-color); }
        .file-indicator.medium { background: var(--medium-color); }
        .file-indicator.low { background: var(--low-color); }

        .file-name {
            flex: 1;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
            font-family: 'SF Mono', Consolas, monospace;
        }

        .file-count {
            font-size: 11px;
            color: var(--text-muted);
        }

        .file-expand-icon {
            color: var(--text-muted);
            font-size: 12px;
            transition: transform 0.2s ease;
        }

        .file-group.collapsed .file-expand-icon {
            transform: rotate(-90deg);
        }

        .file-group.collapsed .file-findings {
            display: none;
        }

        .file-findings {
            padding: 12px;
        }

        /* Resource Groups */
        .resource-group {
            margin-bottom: 8px;
        }

        .resource-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            background: var(--bg-primary);
            border: 1px solid var(--border-subtle);
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .resource-header:hover {
            border-color: var(--border-default);
        }

        .resource-indicator {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }

        .resource-indicator.critical { background: var(--critical-color); }
        .resource-indicator.high { background: var(--high-color); }
        .resource-indicator.medium { background: var(--medium-color); }
        .resource-indicator.low { background: var(--low-color); }

        .resource-name {
            flex: 1;
            font-size: 12px;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .resource-count {
            font-size: 10px;
            color: var(--text-muted);
        }

        .resource-expand-icon {
            color: var(--text-muted);
            font-size: 10px;
            transition: transform 0.2s ease;
        }

        .resource-group.collapsed .resource-expand-icon {
            transform: rotate(-90deg);
        }

        .resource-group.collapsed .resource-findings {
            display: none;
        }

        .resource-findings {
            padding: 8px 0 8px 20px;
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
            gap: 8px;
            margin-bottom: 20px;
        }

        .type-tab {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
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
            padding: 2px 8px;
            background: var(--bg-primary);
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
        }

        .type-tab.active .count {
            background: rgba(209, 35, 42, 0.15);
        }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 0;
            margin-bottom: 28px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .tab {
            padding: 12px 20px;
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.15s ease;
            display: flex;
            align-items: center;
            gap: 8px;
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
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
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
        <h1>Security Scan Results</h1>
        <div class="header-meta">
            <span>${total} issues found</span>
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

            html += `
            <div class="file-group" data-file="${this.escapeHtml(file)}">
                <div class="file-header" onclick="toggleFile('${this.escapeHtml(file).replace(/'/g, "\\'")}')">
                    <span class="file-indicator ${fileSevClass}"></span>
                    <span class="file-name">${this.escapeHtml(fileName)}</span>
                    <span class="file-count">${fileFindings.length} issues</span>
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

                html += `
                    <div class="finding-row" id="finding-${findingIndex}" data-severity="${sevClass}">
                        <div class="finding-header" onclick="toggleFinding(${findingIndex})">
                            <div class="severity-indicator ${sevClass}"></div>
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
                    <div class="llm-icon">AI</div>
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
