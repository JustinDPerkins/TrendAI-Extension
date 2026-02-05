import * as vscode from 'vscode';
import { TmasScanResult, TmasVulnerability, TmasSecret, flattenFindings } from '../scanners/tmas';
import { TemplateScanResult, TemplateScanFinding } from '../scanners/templateScanner';
import { severityToNumber, SeverityLevel, meetsThreshold } from '../config/settings';

export interface DiagnosticMetadata {
    type: 'vulnerability' | 'secret' | 'malware' | 'iac';
    source: 'tmas' | 'template-scanner';
    ruleId?: string;
    fixVersion?: string;
    link?: string;
}

export class DiagnosticsProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private severityThreshold: SeverityLevel;

    constructor(severityThreshold: SeverityLevel = 'medium') {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('trendai');
        this.severityThreshold = severityThreshold;
    }

    setSeverityThreshold(threshold: SeverityLevel): void {
        this.severityThreshold = threshold;
    }

    clearDiagnostics(uri?: vscode.Uri): void {
        if (uri) {
            this.diagnosticCollection.delete(uri);
        } else {
            this.diagnosticCollection.clear();
        }
    }

    addTmasResults(result: TmasScanResult, baseUri: vscode.Uri): void {
        const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();

        // Process vulnerabilities (findings can be grouped by severity)
        const vulnFindings = flattenFindings<TmasVulnerability>(result.vulnerabilities?.findings);
        for (const vuln of vulnFindings) {
            if (!meetsThreshold(vuln.severity, this.severityThreshold)) {
                continue;
            }

            const diagnostic = this.createVulnerabilityDiagnostic(vuln);
            const filePath = baseUri.fsPath;

            if (!diagnosticsByFile.has(filePath)) {
                diagnosticsByFile.set(filePath, []);
            }
            diagnosticsByFile.get(filePath)!.push(diagnostic);
        }

        // Process secrets (findings can be grouped by severity)
        const secretFindings = flattenFindings<TmasSecret>(result.secrets?.findings);
        for (const secret of secretFindings) {
            const diagnostic = this.createSecretDiagnostic(secret);
            const filePath = secret.file
                ? vscode.Uri.joinPath(baseUri, secret.file).fsPath
                : baseUri.fsPath;

            if (!diagnosticsByFile.has(filePath)) {
                diagnosticsByFile.set(filePath, []);
            }
            diagnosticsByFile.get(filePath)!.push(diagnostic);
        }

        // Process malware
        const malwareFindings = flattenFindings(result.malware?.findings);
        for (const malware of malwareFindings) {
            if (malware.foundMalwares) {
                for (const m of malware.foundMalwares) {
                    const diagnostic = this.createMalwareDiagnostic(m.malwareName, malware.fileName);
                    const filePath = malware.fileName
                        ? vscode.Uri.joinPath(baseUri, malware.fileName).fsPath
                        : baseUri.fsPath;

                    if (!diagnosticsByFile.has(filePath)) {
                        diagnosticsByFile.set(filePath, []);
                    }
                    diagnosticsByFile.get(filePath)!.push(diagnostic);
                }
            }
        }

        // Set diagnostics for each file
        for (const [filePath, diagnostics] of diagnosticsByFile) {
            const uri = vscode.Uri.file(filePath);
            const existing = this.diagnosticCollection.get(uri) || [];
            this.diagnosticCollection.set(uri, [...existing, ...diagnostics]);
        }
    }

    addTemplateScanResults(result: TemplateScanResult, fileUri: vscode.Uri): void {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const finding of result.findings) {
            if (!meetsThreshold(finding.severity, this.severityThreshold)) {
                continue;
            }

            const diagnostic = this.createTemplateFindingDiagnostic(finding);
            diagnostics.push(diagnostic);
        }

        const existing = this.diagnosticCollection.get(fileUri) || [];
        this.diagnosticCollection.set(fileUri, [...existing, ...diagnostics]);
    }

    private createVulnerabilityDiagnostic(vuln: TmasVulnerability): vscode.Diagnostic {
        const range = new vscode.Range(0, 0, 0, 0);

        const message = this.formatVulnerabilityMessage(vuln);
        const severity = this.mapSeverity(vuln.severity);

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'TrendAI™ (TMAS)';
        diagnostic.code = {
            value: vuln.id,
            target: vuln.link ? vscode.Uri.parse(vuln.link) : vscode.Uri.parse(`https://nvd.nist.gov/vuln/detail/${vuln.id}`)
        };

        // Store metadata for code actions
        (diagnostic as DiagnosticWithMetadata).metadata = {
            type: 'vulnerability',
            source: 'tmas',
            ruleId: vuln.id,
            fixVersion: vuln.fixedVersion,
            link: vuln.link
        };

        return diagnostic;
    }

    private createSecretDiagnostic(secret: TmasSecret): vscode.Diagnostic {
        const startLine = (secret.startLine || 1) - 1;
        const endLine = (secret.endLine || secret.startLine || 1) - 1;
        const startCol = (secret.startColumn || 1) - 1;
        const endCol = (secret.endColumn || 100) - 1;

        const range = new vscode.Range(startLine, startCol, endLine, endCol);
        const message = `Secret detected: ${secret.description || secret.ruleID}`;

        const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Error);
        diagnostic.source = 'TrendAI™ (TMAS)';
        diagnostic.code = secret.ruleID;

        (diagnostic as DiagnosticWithMetadata).metadata = {
            type: 'secret',
            source: 'tmas',
            ruleId: secret.ruleID
        };

        return diagnostic;
    }

    private createMalwareDiagnostic(malwareName: string, fileName?: string): vscode.Diagnostic {
        const range = new vscode.Range(0, 0, 0, 0);
        const message = `Malware detected: ${malwareName}${fileName ? ` in ${fileName}` : ''}`;

        const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Error);
        diagnostic.source = 'TrendAI™ (TMAS)';

        (diagnostic as DiagnosticWithMetadata).metadata = {
            type: 'malware',
            source: 'tmas'
        };

        return diagnostic;
    }

    private createTemplateFindingDiagnostic(finding: TemplateScanFinding): vscode.Diagnostic {
        const line = (finding.line || 1) - 1;
        const col = (finding.column || 1) - 1;
        const range = new vscode.Range(line, col, line, col + 50);

        const message = this.formatTemplateFindingMessage(finding);
        const severity = this.mapSeverity(finding.severity);

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'TrendAI™ (Template Scanner)';
        diagnostic.code = finding.link
            ? { value: finding.ruleId, target: vscode.Uri.parse(finding.link) }
            : finding.ruleId;

        (diagnostic as DiagnosticWithMetadata).metadata = {
            type: 'iac',
            source: 'template-scanner',
            ruleId: finding.ruleId,
            link: finding.link
        };

        return diagnostic;
    }

    private formatVulnerabilityMessage(vuln: TmasVulnerability): string {
        let message = `[${vuln.severity.toUpperCase()}] ${vuln.id}`;

        if (vuln.packageName) {
            message += ` in ${vuln.packageName}`;
            if (vuln.installedVersion) {
                message += `@${vuln.installedVersion}`;
            }
        }

        if (vuln.title) {
            message += `: ${vuln.title}`;
        }

        if (vuln.fixedVersion) {
            message += ` (fix available: ${vuln.fixedVersion})`;
        }

        return message;
    }

    private formatTemplateFindingMessage(finding: TemplateScanFinding): string {
        let message = `[${finding.severity.toUpperCase()}] ${finding.ruleName || finding.ruleId}`;

        if (finding.resource) {
            message += ` on ${finding.resource}`;
        }

        if (finding.description) {
            message += `: ${finding.description}`;
        }

        return message;
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        const level = severityToNumber(severity);

        if (level >= 4) { // critical or high
            return vscode.DiagnosticSeverity.Error;
        } else if (level >= 3) { // medium
            return vscode.DiagnosticSeverity.Warning;
        } else { // low or negligible
            return vscode.DiagnosticSeverity.Information;
        }
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}

export interface DiagnosticWithMetadata extends vscode.Diagnostic {
    metadata?: DiagnosticMetadata;
}
