import * as vscode from 'vscode';
import { TmasScanResult, TmasVulnerability, TmasSecret, TmasMalware, flattenFindings } from '../scanners/tmas';
import { TemplateScanResult, TemplateScanFinding } from '../scanners/templateScanner';
import { severityToNumber } from '../config/settings';

export type ResultItemType = 'category' | 'file' | 'vulnerability' | 'secret' | 'malware' | 'iac-finding';

export interface ResultItem {
    type: ResultItemType;
    label: string;
    description?: string;
    severity?: string;
    filePath?: string;
    line?: number;
    column?: number;
    children?: ResultItem[];
    data?: unknown;
}

export class ResultsTreeProvider implements vscode.TreeDataProvider<ResultItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<ResultItem | undefined | null>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private results: ResultItem[] = [];
    private tmasResults: Map<string, TmasScanResult> = new Map();
    private templateResults: Map<string, TemplateScanResult> = new Map();

    refresh(): void {
        this.buildTree();
        this._onDidChangeTreeData.fire(undefined);
    }

    clear(): void {
        this.tmasResults.clear();
        this.templateResults.clear();
        this.results = [];
        this._onDidChangeTreeData.fire(undefined);
    }

    addTmasResult(filePath: string, result: TmasScanResult): void {
        this.tmasResults.set(filePath, result);
        this.refresh();
    }

    addTemplateResult(filePath: string, result: TemplateScanResult): void {
        this.templateResults.set(filePath, result);
        this.refresh();
    }

    private buildTree(): void {
        this.results = [];

        // Build vulnerabilities category
        const vulnerabilities = this.collectVulnerabilities();
        if (vulnerabilities.length > 0) {
            this.results.push({
                type: 'category',
                label: `Vulnerabilities (${vulnerabilities.length})`,
                children: vulnerabilities
            });
        }

        // Build secrets category
        const secrets = this.collectSecrets();
        if (secrets.length > 0) {
            this.results.push({
                type: 'category',
                label: `Secrets (${secrets.length})`,
                children: secrets
            });
        }

        // Build malware category
        const malware = this.collectMalware();
        if (malware.length > 0) {
            this.results.push({
                type: 'category',
                label: `Malware (${malware.length})`,
                children: malware
            });
        }

        // Build IaC findings category
        const iacFindings = this.collectIaCFindings();
        if (iacFindings.length > 0) {
            this.results.push({
                type: 'category',
                label: `IaC Misconfigurations (${iacFindings.length})`,
                children: iacFindings
            });
        }
    }

    private collectVulnerabilities(): ResultItem[] {
        const items: ResultItem[] = [];

        for (const [filePath, result] of this.tmasResults) {
            const findings = flattenFindings<TmasVulnerability>(result.vulnerabilities?.findings);
            for (const vuln of findings) {
                items.push(this.createVulnerabilityItem(vuln, filePath));
            }
        }

        // Sort by severity (critical first)
        return items.sort((a, b) => severityToNumber(b.severity || '') - severityToNumber(a.severity || ''));
    }

    private collectSecrets(): ResultItem[] {
        const items: ResultItem[] = [];

        for (const [basePath, result] of this.tmasResults) {
            const findings = flattenFindings<TmasSecret>(result.secrets?.findings);
            for (const secret of findings) {
                items.push(this.createSecretItem(secret, basePath));
            }
        }

        return items;
    }

    private collectMalware(): ResultItem[] {
        const items: ResultItem[] = [];

        for (const [basePath, result] of this.tmasResults) {
            const findings = flattenFindings<TmasMalware>(result.malware?.findings);
            for (const malware of findings) {
                if (malware.foundMalwares) {
                    for (const m of malware.foundMalwares) {
                        items.push(this.createMalwareItem(m.malwareName, malware.fileName, basePath));
                    }
                }
            }
        }

        return items;
    }

    private collectIaCFindings(): ResultItem[] {
        const items: ResultItem[] = [];

        for (const [filePath, result] of this.templateResults) {
            for (const finding of result.findings) {
                items.push(this.createIaCFindingItem(finding, filePath));
            }
        }

        // Sort by severity
        return items.sort((a, b) => severityToNumber(b.severity || '') - severityToNumber(a.severity || ''));
    }

    private createVulnerabilityItem(vuln: TmasVulnerability, filePath: string): ResultItem {
        let label = vuln.id;
        if (vuln.packageName) {
            label += ` (${vuln.packageName})`;
        }

        return {
            type: 'vulnerability',
            label,
            description: vuln.title || vuln.description,
            severity: vuln.severity,
            filePath,
            data: vuln
        };
    }

    private createSecretItem(secret: TmasSecret, basePath: string): ResultItem {
        const filePath = secret.file
            ? vscode.Uri.joinPath(vscode.Uri.file(basePath), secret.file).fsPath
            : basePath;

        return {
            type: 'secret',
            label: secret.ruleID,
            description: secret.description,
            severity: 'high',
            filePath,
            line: secret.startLine,
            column: secret.startColumn,
            data: secret
        };
    }

    private createMalwareItem(malwareName: string, fileName: string | undefined, basePath: string): ResultItem {
        const filePath = fileName
            ? vscode.Uri.joinPath(vscode.Uri.file(basePath), fileName).fsPath
            : basePath;

        return {
            type: 'malware',
            label: malwareName,
            description: fileName,
            severity: 'critical',
            filePath,
            data: { malwareName, fileName }
        };
    }

    private createIaCFindingItem(finding: TemplateScanFinding, filePath: string): ResultItem {
        return {
            type: 'iac-finding',
            label: finding.ruleName || finding.ruleId,
            description: finding.description,
            severity: finding.severity,
            filePath: finding.file || filePath,
            line: finding.line,
            column: finding.column,
            data: finding
        };
    }

    getTreeItem(element: ResultItem): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(
            element.label,
            element.children
                ? vscode.TreeItemCollapsibleState.Expanded
                : vscode.TreeItemCollapsibleState.None
        );

        treeItem.description = element.description;
        treeItem.tooltip = this.createTooltip(element);
        treeItem.iconPath = this.getIcon(element);

        if (element.filePath && element.type !== 'category') {
            treeItem.command = {
                command: 'vscode.open',
                title: 'Open File',
                arguments: [
                    vscode.Uri.file(element.filePath),
                    {
                        selection: element.line
                            ? new vscode.Range(
                                (element.line || 1) - 1,
                                (element.column || 1) - 1,
                                (element.line || 1) - 1,
                                (element.column || 1) + 50
                            )
                            : undefined
                    }
                ]
            };
        }

        return treeItem;
    }

    getChildren(element?: ResultItem): Thenable<ResultItem[]> {
        if (!element) {
            return Promise.resolve(this.results);
        }
        return Promise.resolve(element.children || []);
    }

    private createTooltip(element: ResultItem): vscode.MarkdownString {
        const md = new vscode.MarkdownString();

        if (element.type === 'vulnerability') {
            const vuln = element.data as TmasVulnerability;
            md.appendMarkdown(`## ${vuln.id}\n\n`);
            md.appendMarkdown(`**Severity:** ${vuln.severity}\n\n`);
            if (vuln.title) {
                md.appendMarkdown(`**Title:** ${vuln.title}\n\n`);
            }
            if (vuln.description) {
                md.appendMarkdown(`${vuln.description}\n\n`);
            }
            if (vuln.packageName) {
                md.appendMarkdown(`**Package:** ${vuln.packageName}@${vuln.installedVersion || 'unknown'}\n\n`);
            }
            if (vuln.fixedVersion) {
                md.appendMarkdown(`**Fixed in:** ${vuln.fixedVersion}\n\n`);
            }
            if (vuln.link) {
                md.appendMarkdown(`[More Info](${vuln.link})`);
            }
        } else if (element.type === 'secret') {
            const secret = element.data as TmasSecret;
            md.appendMarkdown(`## Secret Detected\n\n`);
            md.appendMarkdown(`**Rule:** ${secret.ruleID}\n\n`);
            if (secret.description) {
                md.appendMarkdown(`${secret.description}\n\n`);
            }
            if (secret.file) {
                md.appendMarkdown(`**File:** ${secret.file}:${secret.startLine}\n\n`);
            }
        } else if (element.type === 'iac-finding') {
            const finding = element.data as TemplateScanFinding;
            md.appendMarkdown(`## ${finding.ruleName || finding.ruleId}\n\n`);
            md.appendMarkdown(`**Severity:** ${finding.severity}\n\n`);
            if (finding.description) {
                md.appendMarkdown(`${finding.description}\n\n`);
            }
            if (finding.resource) {
                md.appendMarkdown(`**Resource:** ${finding.resource}\n\n`);
            }
            if (finding.recommendation) {
                md.appendMarkdown(`**Recommendation:** ${finding.recommendation}\n\n`);
            }
            if (finding.link) {
                md.appendMarkdown(`[More Info](${finding.link})`);
            }
        }

        return md;
    }

    private getIcon(element: ResultItem): vscode.ThemeIcon {
        if (element.type === 'category') {
            return new vscode.ThemeIcon('folder');
        }

        const severity = element.severity?.toLowerCase();

        if (element.type === 'malware') {
            return new vscode.ThemeIcon('bug', new vscode.ThemeColor('errorForeground'));
        }

        if (severity === 'critical' || severity === 'high') {
            return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
        } else if (severity === 'medium') {
            return new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'));
        } else {
            return new vscode.ThemeIcon('info', new vscode.ThemeColor('foreground'));
        }
    }

    getTotalCount(): number {
        let count = 0;

        for (const result of this.tmasResults.values()) {
            // Use flattenFindings to count actual findings (consistent with results panel)
            count += flattenFindings<TmasVulnerability>(result.vulnerabilities?.findings).length;
            count += flattenFindings<TmasSecret>(result.secrets?.findings).length;
            count += flattenFindings<TmasMalware>(result.malware?.findings).length;
        }

        for (const result of this.templateResults.values()) {
            count += result.findings.length;
        }

        return count;
    }
}
