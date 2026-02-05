import * as vscode from 'vscode';
import { DiagnosticWithMetadata, DiagnosticMetadata } from './diagnostics';

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            const metadata = (diagnostic as DiagnosticWithMetadata).metadata;

            if (!metadata) {
                continue;
            }

            if (diagnostic.source?.startsWith('TrendAI')) {
                actions.push(...this.createActionsForDiagnostic(document, diagnostic, metadata));
            }
        }

        return actions;
    }

    private createActionsForDiagnostic(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        metadata: DiagnosticMetadata
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Add "Learn More" action for all types
        if (metadata.link) {
            const learnMore = new vscode.CodeAction(
                `Learn more about ${metadata.ruleId}`,
                vscode.CodeActionKind.QuickFix
            );
            learnMore.command = {
                command: 'vscode.open',
                title: 'Learn More',
                arguments: [vscode.Uri.parse(metadata.link)]
            };
            learnMore.diagnostics = [diagnostic];
            actions.push(learnMore);
        } else if (metadata.ruleId && metadata.type === 'vulnerability') {
            // Default to NVD for vulnerabilities
            const learnMore = new vscode.CodeAction(
                `View ${metadata.ruleId} on NVD`,
                vscode.CodeActionKind.QuickFix
            );
            learnMore.command = {
                command: 'vscode.open',
                title: 'View on NVD',
                arguments: [vscode.Uri.parse(`https://nvd.nist.gov/vuln/detail/${metadata.ruleId}`)]
            };
            learnMore.diagnostics = [diagnostic];
            actions.push(learnMore);
        }

        // Type-specific actions
        switch (metadata.type) {
            case 'vulnerability':
                actions.push(...this.createVulnerabilityActions(document, diagnostic, metadata));
                break;
            case 'secret':
                actions.push(...this.createSecretActions(document, diagnostic));
                break;
            case 'iac':
                actions.push(...this.createIaCActions(document, diagnostic, metadata));
                break;
        }

        return actions;
    }

    private createVulnerabilityActions(
        _document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        metadata: DiagnosticMetadata
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        if (metadata.fixVersion) {
            const updateAction = new vscode.CodeAction(
                `Update to fixed version: ${metadata.fixVersion}`,
                vscode.CodeActionKind.QuickFix
            );
            updateAction.diagnostics = [diagnostic];
            updateAction.isPreferred = true;
            // This is informational - actual update would need package manager integration
            updateAction.command = {
                command: 'trendai.showVulnerabilityFix',
                title: 'Show Fix Details',
                arguments: [metadata]
            };
            actions.push(updateAction);
        }

        return actions;
    }

    private createSecretActions(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Add action to remove the secret line
        const removeLine = new vscode.CodeAction(
            'Remove line containing secret',
            vscode.CodeActionKind.QuickFix
        );
        removeLine.diagnostics = [diagnostic];
        removeLine.edit = new vscode.WorkspaceEdit();
        removeLine.edit.delete(document.uri, document.lineAt(diagnostic.range.start.line).rangeIncludingLineBreak);
        actions.push(removeLine);

        // Add action to add to .gitignore
        const addToGitignore = new vscode.CodeAction(
            'Add file to .gitignore',
            vscode.CodeActionKind.QuickFix
        );
        addToGitignore.diagnostics = [diagnostic];
        addToGitignore.command = {
            command: 'trendai.addToGitignore',
            title: 'Add to .gitignore',
            arguments: [document.uri.fsPath]
        };
        actions.push(addToGitignore);

        return actions;
    }

    private createIaCActions(
        _document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        metadata: DiagnosticMetadata
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Suppress finding action
        const suppress = new vscode.CodeAction(
            `Suppress ${metadata.ruleId} with comment`,
            vscode.CodeActionKind.QuickFix
        );
        suppress.diagnostics = [diagnostic];
        suppress.command = {
            command: 'trendai.suppressFinding',
            title: 'Suppress Finding',
            arguments: [diagnostic, metadata]
        };
        actions.push(suppress);

        return actions;
    }
}
