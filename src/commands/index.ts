import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { TmasScanner } from '../scanners/tmas';
import { TemplateScanner } from '../scanners/templateScanner';
import { DiagnosticsProvider } from '../providers/diagnostics';
import { ResultsTreeProvider } from '../providers/treeView';
import { ResultsPanelProvider } from '../providers/resultsPanel';
import { SettingsManager } from '../config/settings';
import { isDirectory, isIaCFile } from '../utils/fileUtils';

export class CommandHandler {
    private tmasScanner: TmasScanner;
    private templateScanner: TemplateScanner;
    private diagnosticsProvider: DiagnosticsProvider;
    private resultsTreeProvider: ResultsTreeProvider;
    private settingsManager: SettingsManager;
    private outputChannel: vscode.OutputChannel;
    private statusBarItem: vscode.StatusBarItem;
    private extensionUri: vscode.Uri;
    private resultsPanel: ResultsPanelProvider | undefined;

    constructor(
        tmasScanner: TmasScanner,
        templateScanner: TemplateScanner,
        diagnosticsProvider: DiagnosticsProvider,
        resultsTreeProvider: ResultsTreeProvider,
        settingsManager: SettingsManager,
        outputChannel: vscode.OutputChannel,
        statusBarItem: vscode.StatusBarItem,
        extensionUri: vscode.Uri
    ) {
        this.tmasScanner = tmasScanner;
        this.templateScanner = templateScanner;
        this.diagnosticsProvider = diagnosticsProvider;
        this.resultsTreeProvider = resultsTreeProvider;
        this.settingsManager = settingsManager;
        this.outputChannel = outputChannel;
        this.statusBarItem = statusBarItem;
        this.extensionUri = extensionUri;
    }

    showResultsPanel(): void {
        this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
    }

    async scanDirectory(uri?: vscode.Uri): Promise<void> {
        const targetPath = await this.getTargetPath(uri, true);
        if (!targetPath) {
            return;
        }

        await this.runWithProgress('Scanning directory...', async () => {
            try {
                const result = await this.tmasScanner.scanDirectory(targetPath);
                this.diagnosticsProvider.addTmasResults(result, vscode.Uri.file(targetPath));
                this.resultsTreeProvider.addTmasResult(targetPath, result);

                // Show results panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addTmasResults(result, targetPath);

                const vulnCount = result.vulnerabilities?.totalVulnCount || 0;
                const secretCount = result.secrets?.totalFilesScanned ? result.secrets.unmitigatedFindingsCount || 0 : 0;

                vscode.window.showInformationMessage(
                    `Scan complete: ${vulnCount} vulnerabilities, ${secretCount} secrets found`
                );

                this.updateStatusBar();
            } catch (error) {
                this.handleError('Directory scan failed', error);
            }
        });
    }

    async scanFile(uri?: vscode.Uri): Promise<void> {
        const targetPath = await this.getTargetPath(uri, false);
        if (!targetPath) {
            return;
        }

        const isDir = isDirectory(targetPath);

        await this.runWithProgress(`Scanning ${isDir ? 'directory' : 'file'}...`, async () => {
            try {
                const result = isDir
                    ? await this.tmasScanner.scanDirectory(targetPath)
                    : await this.tmasScanner.scanFile(targetPath);

                this.diagnosticsProvider.addTmasResults(result, vscode.Uri.file(targetPath));
                this.resultsTreeProvider.addTmasResult(targetPath, result);

                // Show results panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addTmasResults(result, targetPath);

                const vulnCount = result.vulnerabilities?.totalVulnCount || 0;
                const secretCount = result.secrets?.totalFilesScanned ? result.secrets.unmitigatedFindingsCount || 0 : 0;

                vscode.window.showInformationMessage(
                    `Scan complete: ${vulnCount} vulnerabilities, ${secretCount} secrets found`
                );

                this.updateStatusBar();
            } catch (error) {
                this.handleError('File scan failed', error);
            }
        });
    }

    async scanImage(): Promise<void> {
        const imageRef = await vscode.window.showInputBox({
            prompt: 'Enter container image reference',
            placeHolder: 'e.g., nginx:latest, myregistry/myimage:tag',
            ignoreFocusOut: true
        });

        if (!imageRef) {
            return;
        }

        const imageType = await vscode.window.showQuickPick(
            [
                { label: 'Registry', value: 'registry' as const, description: 'Pull from container registry' },
                { label: 'Docker', value: 'docker' as const, description: 'Local Docker daemon image' },
                { label: 'Docker Archive', value: 'docker-archive' as const, description: 'Docker save tarball' }
            ],
            { placeHolder: 'Select image source' }
        );

        if (!imageType) {
            return;
        }

        await this.runWithProgress('Scanning container image...', async () => {
            try {
                const result = await this.tmasScanner.scanImage(imageRef, imageType.value);
                this.resultsTreeProvider.addTmasResult(imageRef, result);

                // Show results panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addTmasResults(result, imageRef);

                const vulnCount = result.vulnerabilities?.totalVulnCount || 0;
                const malwareCount = Array.isArray(result.malware?.findings) ? result.malware.findings.length : 0;
                const secretCount = result.secrets?.unmitigatedFindingsCount || 0;

                vscode.window.showInformationMessage(
                    `Image scan complete: ${vulnCount} vulnerabilities, ${malwareCount} malware, ${secretCount} secrets found`
                );

                this.updateStatusBar();
            } catch (error) {
                this.handleError('Image scan failed', error);
            }
        });
    }

    async scanTemplate(uri?: vscode.Uri): Promise<void> {
        const targetPath = await this.getTargetPath(uri, false);
        if (!targetPath) {
            return;
        }

        if (!isIaCFile(targetPath)) {
            vscode.window.showErrorMessage('Selected file is not a supported IaC template (Terraform or CloudFormation)');
            return;
        }

        await this.runWithProgress('Scanning IaC template...', async () => {
            try {
                let result = await this.templateScanner.scanFile(targetPath);

                // Enrich findings with check details
                result = await this.templateScanner.enrichFindingsWithCheckDetails(result);

                const fileUri = vscode.Uri.file(targetPath);

                this.diagnosticsProvider.addTemplateScanResults(result, fileUri);
                this.resultsTreeProvider.addTemplateResult(targetPath, result);

                // Show results panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addTemplateResults(result, targetPath);

                vscode.window.showInformationMessage(
                    `Template scan complete: ${result.findings.length} issues found`
                );

                this.updateStatusBar();
            } catch (error) {
                this.handleError('Template scan failed', error);
            }
        });
    }

    async scanTerraformProject(uri?: vscode.Uri): Promise<void> {
        const targetPath = await this.getTargetPath(uri, true);
        if (!targetPath) {
            return;
        }

        await this.runWithProgress('Scanning Terraform project...', async () => {
            try {
                let result = await this.templateScanner.scanTerraformProject(targetPath);

                // Enrich findings with check details
                result = await this.templateScanner.enrichFindingsWithCheckDetails(result);

                const dirUri = vscode.Uri.file(targetPath);

                this.diagnosticsProvider.addTemplateScanResults(result, dirUri);
                this.resultsTreeProvider.addTemplateResult(targetPath, result);

                // Show results panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addTemplateResults(result, targetPath);

                vscode.window.showInformationMessage(
                    `Terraform scan complete: ${result.findings.length} issues found`
                );

                this.updateStatusBar();
            } catch (error) {
                this.handleError('Terraform project scan failed', error);
            }
        });
    }

    async setApiToken(): Promise<void> {
        const success = await this.settingsManager.promptForApiToken();
        if (success) {
            await this.templateScanner.initialize();
        }
    }

    refreshResults(): void {
        this.resultsTreeProvider.refresh();
    }

    clearResults(): void {
        this.diagnosticsProvider.clearDiagnostics();
        this.resultsTreeProvider.clear();
        this.updateStatusBar();
        vscode.window.showInformationMessage('All scan results cleared');
    }

    async showVulnerabilityFix(metadata: { ruleId?: string; fixVersion?: string }): Promise<void> {
        const message = metadata.fixVersion
            ? `To fix ${metadata.ruleId}, update the affected package to version ${metadata.fixVersion} or later.`
            : `See the vulnerability details for ${metadata.ruleId} for remediation guidance.`;

        vscode.window.showInformationMessage(message);
    }

    async addToGitignore(filePath: string): Promise<void> {
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(filePath));
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }

        const gitignorePath = path.join(workspaceFolder.uri.fsPath, '.gitignore');
        const relativePath = path.relative(workspaceFolder.uri.fsPath, filePath);

        let content = '';
        if (fs.existsSync(gitignorePath)) {
            content = fs.readFileSync(gitignorePath, 'utf-8');
        }

        if (content.includes(relativePath)) {
            vscode.window.showInformationMessage('File is already in .gitignore');
            return;
        }

        content += `\n${relativePath}\n`;
        fs.writeFileSync(gitignorePath, content);
        vscode.window.showInformationMessage(`Added ${relativePath} to .gitignore`);
    }

    async suppressFinding(diagnostic: vscode.Diagnostic, metadata: { ruleId?: string }): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return;
        }

        const line = diagnostic.range.start.line;
        const suppressComment = this.getSuppressionComment(editor.document.languageId, metadata.ruleId);

        await editor.edit((editBuilder) => {
            editBuilder.insert(new vscode.Position(line, 0), suppressComment);
        });
    }

    async buildAndScanDockerfile(uri?: vscode.Uri): Promise<void> {
        // Get Dockerfile path
        let dockerfilePath: string | undefined;

        if (uri) {
            dockerfilePath = uri.fsPath;
        } else {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor && activeEditor.document.fileName.includes('Dockerfile')) {
                dockerfilePath = activeEditor.document.uri.fsPath;
            } else {
                // Let user browse for Dockerfile
                const result = await vscode.window.showOpenDialog({
                    canSelectFiles: true,
                    canSelectFolders: false,
                    filters: { 'Dockerfile': ['dockerfile', 'Dockerfile', '*'] },
                    openLabel: 'Select Dockerfile'
                });
                if (result && result.length > 0) {
                    dockerfilePath = result[0].fsPath;
                }
            }
        }

        if (!dockerfilePath) {
            return;
        }

        // Get image name from user
        const dockerfileDir = path.dirname(dockerfilePath);
        const defaultImageName = path.basename(dockerfileDir).toLowerCase().replace(/[^a-z0-9-]/g, '-') + ':scan';

        const imageName = await vscode.window.showInputBox({
            prompt: 'Enter image name for the build',
            value: defaultImageName,
            placeHolder: 'e.g., myapp:latest',
            ignoreFocusOut: true
        });

        if (!imageName) {
            return;
        }

        const tempTarPath = path.join(require('os').tmpdir(), `trendai-scan-${Date.now()}.tar`);

        await this.runWithProgress('Building and scanning Docker image...', async () => {
            try {
                // Step 1: Build the Docker image
                this.outputChannel.appendLine(`Building Docker image: ${imageName}`);
                this.outputChannel.appendLine(`Dockerfile: ${dockerfilePath}`);
                this.outputChannel.appendLine(`Context: ${dockerfileDir}`);

                await this.runDockerCommand(`docker build -t ${imageName} -f "${dockerfilePath}" "${dockerfileDir}"`);
                this.outputChannel.appendLine('Docker build completed');

                // Step 2: Save image to tar file
                this.outputChannel.appendLine(`Saving image to: ${tempTarPath}`);
                await this.runDockerCommand(`docker save ${imageName} -o "${tempTarPath}"`);
                this.outputChannel.appendLine('Image saved to tar file');

                // Step 3: Scan with TMAS
                this.outputChannel.appendLine('Starting TMAS scan...');
                const result = await this.tmasScanner.scanImage(tempTarPath, 'docker-archive');

                this.resultsTreeProvider.addTmasResult(imageName, result);

                // Show results panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addTmasResults(result, imageName);

                const vulnCount = result.vulnerabilities?.totalVulnCount || 0;
                const malwareCount = result.malware?.scanResult === 0 ? 0 : 1;
                const secretCount = result.secrets?.unmitigatedFindingsCount || 0;

                vscode.window.showInformationMessage(
                    `Docker scan complete: ${vulnCount} vulnerabilities, ${malwareCount} malware, ${secretCount} secrets found`
                );

                this.updateStatusBar();
            } catch (error) {
                this.handleError('Docker build & scan failed', error);
            } finally {
                // Clean up temp file
                try {
                    if (fs.existsSync(tempTarPath)) {
                        fs.unlinkSync(tempTarPath);
                        this.outputChannel.appendLine('Cleaned up temp tar file');
                    }
                } catch (cleanupError) {
                    this.outputChannel.appendLine(`Warning: Failed to clean up temp file: ${cleanupError}`);
                }
            }
        });
    }

    private runDockerCommand(command: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const { exec } = require('child_process');
            this.outputChannel.appendLine(`Running: ${command}`);

            exec(command, { maxBuffer: 50 * 1024 * 1024 }, (error: Error | null, stdout: string, stderr: string) => {
                if (stdout) {
                    this.outputChannel.appendLine(stdout);
                }
                if (stderr) {
                    this.outputChannel.appendLine(stderr);
                }
                if (error) {
                    reject(new Error(`Docker command failed: ${error.message}\n${stderr}`));
                } else {
                    resolve();
                }
            });
        });
    }

    private getSuppressionComment(languageId: string, ruleId?: string): string {
        const rule = ruleId || 'rule';

        switch (languageId) {
            case 'terraform':
            case 'hcl':
                return `# tfsec:ignore:${rule}\n`;
            case 'yaml':
            case 'cloudformation':
                return `# cfsec:ignore:${rule}\n`;
            case 'json':
                return ''; // JSON doesn't support comments
            default:
                return `# ignore:${rule}\n`;
        }
    }

    private async getTargetPath(uri: vscode.Uri | undefined, preferDirectory: boolean): Promise<string | undefined> {
        if (uri) {
            return uri.fsPath;
        }

        // Try active editor
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor && !preferDirectory) {
            return activeEditor.document.uri.fsPath;
        }

        // Try workspace folder
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            if (workspaceFolders.length === 1) {
                return workspaceFolders[0].uri.fsPath;
            }

            // Let user pick workspace folder
            const selected = await vscode.window.showWorkspaceFolderPick({
                placeHolder: 'Select workspace folder to scan'
            });

            if (selected) {
                return selected.uri.fsPath;
            }
        }

        // Let user browse
        const options: vscode.OpenDialogOptions = preferDirectory
            ? { canSelectFolders: true, canSelectFiles: false, openLabel: 'Select Directory' }
            : { canSelectFolders: true, canSelectFiles: true, openLabel: 'Select File or Directory' };

        const result = await vscode.window.showOpenDialog(options);
        if (result && result.length > 0) {
            return result[0].fsPath;
        }

        return undefined;
    }

    private async runWithProgress<T>(title: string, task: () => Promise<T>): Promise<T | undefined> {
        this.setScanning(true);

        try {
            return await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title,
                    cancellable: false
                },
                async () => task()
            );
        } finally {
            this.setScanning(false);
        }
    }

    private setScanning(scanning: boolean): void {
        if (scanning) {
            this.statusBarItem.text = '$(sync~spin) TrendAI™: Scanning...';
        } else {
            this.updateStatusBar();
        }
    }

    private updateStatusBar(): void {
        const count = this.resultsTreeProvider.getTotalCount();
        if (count > 0) {
            this.statusBarItem.text = `$(shield) TrendAI™: ${count} issues`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
            this.statusBarItem.text = '$(shield) TrendAI™';
            this.statusBarItem.backgroundColor = undefined;
        }
    }

    private handleError(message: string, error: unknown): void {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.outputChannel.appendLine(`ERROR: ${message}: ${errorMessage}`);

        // Log full error details including API response
        if (error && typeof error === 'object' && 'response' in error) {
            this.outputChannel.appendLine(`API Response: ${JSON.stringify((error as { response: unknown }).response, null, 2)}`);
        }

        vscode.window.showErrorMessage(`${message}: ${errorMessage}`);
    }

    async launchAIScanner(): Promise<void> {
        try {
            // Ensure TMAS is installed
            const tmasPath = await this.tmasScanner.ensureTmasInstalled();
            const apiToken = await this.settingsManager.getApiToken();

            if (!apiToken) {
                const action = await vscode.window.showErrorMessage(
                    'API token not configured. Configure now?',
                    'Configure',
                    'Cancel'
                );
                if (action === 'Configure') {
                    await this.setApiToken();
                }
                return;
            }

            // Get region setting
            const settings = this.settingsManager.getSettings();
            const regionArg = settings.tmasRegion !== 'us-east-1' ? ` --region=${settings.tmasRegion}` : '';

            // Create a terminal with the API token in environment
            const terminal = vscode.window.createTerminal({
                name: 'TrendAI™ AI Scanner',
                env: {
                    'TMAS_API_KEY': apiToken
                }
            });

            // Show the terminal and run the command
            terminal.show();
            terminal.sendText(`"${tmasPath}" aiscan llm -i${regionArg}`);

            this.outputChannel.appendLine('Launched AI Scanner in terminal');
        } catch (error) {
            this.handleError('Failed to launch AI Scanner', error);
        }
    }
}
