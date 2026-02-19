import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { TmasScanner } from '../scanners/tmas';
import { TemplateScanner } from '../scanners/templateScanner';
import { LLMScanner, ENDPOINT_CONFIGS, ATTACK_OBJECTIVES, ATTACK_TECHNIQUES, ATTACK_MODIFIERS, LLMEndpointType, LLMScanConfig, SavedLLMConfig, DiscoveredModel } from '../scanners/llmScanner';
import { DiagnosticsProvider } from '../providers/diagnostics';
import { ResultsTreeProvider } from '../providers/treeView';
import { ResultsPanelProvider } from '../providers/resultsPanel';
import { SettingsManager } from '../config/settings';
import { isDirectory, isIaCFile, findIaCFiles } from '../utils/fileUtils';
import { parseError, toScanError } from '../utils/errors';

export class CommandHandler {
    private tmasScanner: TmasScanner;
    private templateScanner: TemplateScanner;
    private llmScanner: LLMScanner;
    private diagnosticsProvider: DiagnosticsProvider;
    private resultsTreeProvider: ResultsTreeProvider;
    private settingsManager: SettingsManager;
    private outputChannel: vscode.OutputChannel;
    private statusBarItem: vscode.StatusBarItem;
    private extensionUri: vscode.Uri;
    private context: vscode.ExtensionContext;
    private resultsPanel: ResultsPanelProvider | undefined;

    constructor(
        tmasScanner: TmasScanner,
        templateScanner: TemplateScanner,
        diagnosticsProvider: DiagnosticsProvider,
        resultsTreeProvider: ResultsTreeProvider,
        settingsManager: SettingsManager,
        outputChannel: vscode.OutputChannel,
        statusBarItem: vscode.StatusBarItem,
        extensionUri: vscode.Uri,
        context: vscode.ExtensionContext
    ) {
        this.tmasScanner = tmasScanner;
        this.templateScanner = templateScanner;
        this.diagnosticsProvider = diagnosticsProvider;
        this.resultsTreeProvider = resultsTreeProvider;
        this.settingsManager = settingsManager;
        this.outputChannel = outputChannel;
        this.statusBarItem = statusBarItem;
        this.extensionUri = extensionUri;
        this.context = context;
        this.llmScanner = new LLMScanner(settingsManager, outputChannel, context);
    }

    showResultsPanel(): void {
        this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
        // Load historical results if panel is empty
        this.loadHistoricalResults();
    }

    private loadHistoricalResults(): void {
        const resultsDir = this.getScansDir();
        if (!fs.existsSync(resultsDir)) {
            return;
        }

        try {
            const files = fs.readdirSync(resultsDir).sort().reverse();

            // Load most recent IaC scan
            const iacFile = files.find(f => f.startsWith('iac-scan-') && f.endsWith('.json'));
            if (iacFile && this.resultsPanel) {
                const content = fs.readFileSync(path.join(resultsDir, iacFile), 'utf-8');
                const scanRecord = JSON.parse(content);
                if (scanRecord.result) {
                    this.resultsPanel.addTmasResults(scanRecord.result, scanRecord.target || 'Unknown');
                }
            }

            // Load most recent LLM scan
            const llmFile = files.find(f => f.startsWith('llm-scan-') && f.endsWith('.json'));
            if (llmFile && this.resultsPanel) {
                const content = fs.readFileSync(path.join(resultsDir, llmFile), 'utf-8');
                const llmResult = JSON.parse(content);
                if (llmResult.details && llmResult.results) {
                    this.resultsPanel.addLLMResults(llmResult);
                }
            }
        } catch (error) {
            this.outputChannel.appendLine(`Failed to load historical results: ${error}`);
        }
    }

    /**
     * Unified scan command - scans for everything:
     * - IaC misconfigurations (Terraform, CloudFormation)
     * - Vulnerabilities (dependencies, packages)
     * - Secrets (API keys, passwords, tokens)
     *
     * Works on:
     * - Right-click folder: scans that folder recursively
     * - Right-click file: scans the file's parent folder
     * - Command palette: scans entire workspace
     */
    async scan(uri?: vscode.Uri): Promise<void> {
        // Determine scan target
        let targetPath: string;

        if (uri) {
            // Right-click context: use the clicked path
            // If it's a file, use its parent directory
            targetPath = isDirectory(uri.fsPath) ? uri.fsPath : path.dirname(uri.fsPath);
        } else {
            // Command palette: use workspace folder
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders || workspaceFolders.length === 0) {
                vscode.window.showErrorMessage('No workspace folder open');
                return;
            }

            if (workspaceFolders.length === 1) {
                targetPath = workspaceFolders[0].uri.fsPath;
            } else {
                const selected = await vscode.window.showWorkspaceFolderPick({
                    placeHolder: 'Select workspace folder to scan'
                });
                if (!selected) return;
                targetPath = selected.uri.fsPath;
            }
        }

        const folderName = path.basename(targetPath);

        await this.runWithProgress(`Scanning ${folderName}...`, async () => {
            try {
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.clear();
                this.resultsPanel.setScanning(true);

                let totalIaCFindings = 0;
                let totalVulns = 0;
                let totalSecrets = 0;
                let successfulScans = 0;
                let failedScans = 0;
                const scanErrors: Array<{ file: string; error: unknown }> = [];

                // Step 1: Find and scan IaC files
                this.outputChannel.appendLine(`\n${'='.repeat(50)}`);
                this.outputChannel.appendLine(`TrendAI Scan: ${targetPath}`);
                this.outputChannel.appendLine(`${'='.repeat(50)}`);
                this.outputChannel.appendLine('\n[1/2] Scanning for IaC misconfigurations...');

                const iacFiles = findIaCFiles(targetPath);

                if (iacFiles.terraform.length > 0 || iacFiles.cloudformation.length > 0) {
                    this.outputChannel.appendLine(`  Found ${iacFiles.terraform.length} Terraform files, ${iacFiles.cloudformation.length} CloudFormation files`);

                    // Group Terraform files by directory, but only scan root directories
                    // (not subdirectories that are part of the same project)
                    if (iacFiles.terraform.length > 0) {
                        const allTfDirs = new Set<string>();
                        for (const tfFile of iacFiles.terraform) {
                            allTfDirs.add(path.dirname(tfFile));
                        }

                        // Filter to only root Terraform directories
                        // Skip any directory whose parent is also in the set
                        const tfDirs = [...allTfDirs].filter(dir => {
                            // Check if any parent directory is also in the set
                            let parent = path.dirname(dir);
                            while (parent !== dir && parent.startsWith(targetPath)) {
                                if (allTfDirs.has(parent)) {
                                    // Parent is a Terraform directory, skip this one
                                    return false;
                                }
                                dir = parent;
                                parent = path.dirname(dir);
                            }
                            return true;
                        });

                        this.outputChannel.appendLine(`  Scanning ${tfDirs.length} Terraform project(s)...`);

                        for (const tfDir of tfDirs) {
                            try {
                                const shortPath = tfDir.replace(targetPath, '.') || '.';
                                this.outputChannel.appendLine(`    Terraform project: ${shortPath}`);

                                let result = await this.templateScanner.scanTerraformProject(tfDir);
                                result = await this.templateScanner.enrichFindingsWithCheckDetails(result);

                                // Add results for each file in the directory
                                const tfFilesInDir = iacFiles.terraform.filter(f => path.dirname(f) === tfDir);
                                for (const tfFile of tfFilesInDir) {
                                    const fileUri = vscode.Uri.file(tfFile);
                                    // Filter findings for this specific file if possible
                                    this.diagnosticsProvider.addTemplateScanResults(result, fileUri);
                                }
                                this.resultsTreeProvider.addTemplateResult(tfDir, result);
                                this.resultsPanel.addTemplateResults(result, tfDir);

                                totalIaCFindings += result.findings.length;
                                successfulScans++;
                            } catch (err) {
                                this.outputChannel.appendLine(`    Failed: ${tfDir} - ${err}`);
                                failedScans++;
                                scanErrors.push({ file: tfDir, error: err });

                                const parsed = parseError(err);
                                this.resultsPanel.addError(toScanError(parsed, tfDir));
                            }
                        }
                    }

                    // Scan CloudFormation files individually (they don't need project context)
                    for (const filePath of iacFiles.cloudformation) {
                        try {
                            const shortPath = filePath.replace(targetPath, '.');
                            this.outputChannel.appendLine(`  Scanning: ${shortPath}`);

                            let result = await this.templateScanner.scanFile(filePath);
                            result = await this.templateScanner.enrichFindingsWithCheckDetails(result);

                            const fileUri = vscode.Uri.file(filePath);
                            this.diagnosticsProvider.addTemplateScanResults(result, fileUri);
                            this.resultsTreeProvider.addTemplateResult(filePath, result);
                            this.resultsPanel.addTemplateResults(result, filePath);

                            totalIaCFindings += result.findings.length;
                            successfulScans++;
                        } catch (err) {
                            this.outputChannel.appendLine(`  Failed: ${filePath} - ${err}`);
                            failedScans++;
                            scanErrors.push({ file: filePath, error: err });

                            const parsed = parseError(err);
                            this.resultsPanel.addError(toScanError(parsed, filePath));
                        }
                    }

                    this.outputChannel.appendLine(`  IaC scan complete: ${totalIaCFindings} issues found`);
                } else {
                    this.outputChannel.appendLine('  No IaC files found');
                }

                // Step 2: Scan for vulnerabilities and secrets with TMAS
                this.outputChannel.appendLine('\n[2/2] Scanning for vulnerabilities and secrets...');

                let tmasSuccess = false;
                try {
                    const tmasResult = await this.tmasScanner.scanDirectory(targetPath);
                    this.diagnosticsProvider.addTmasResults(tmasResult, vscode.Uri.file(targetPath));
                    this.resultsTreeProvider.addTmasResult(targetPath, tmasResult);
                    this.resultsPanel.addTmasResults(tmasResult, targetPath);

                    totalVulns = tmasResult.vulnerabilities?.totalVulnCount || 0;
                    totalSecrets = tmasResult.secrets?.unmitigatedFindingsCount || 0;
                    tmasSuccess = true;
                    successfulScans++;
                } catch (err) {
                    this.outputChannel.appendLine(`  TMAS scan failed: ${err}`);
                    failedScans++;
                    scanErrors.push({ file: targetPath, error: err });

                    const parsed = parseError(err);
                    this.resultsPanel.addError(toScanError(parsed, targetPath));
                }

                if (tmasSuccess) {
                    this.outputChannel.appendLine(`  Vulnerabilities: ${totalVulns}`);
                    this.outputChannel.appendLine(`  Secrets: ${totalSecrets}`);
                }

                // Summary
                this.outputChannel.appendLine(`\n${'='.repeat(50)}`);
                this.outputChannel.appendLine('SCAN COMPLETE');
                this.outputChannel.appendLine(`  IaC Issues: ${totalIaCFindings}`);
                this.outputChannel.appendLine(`  Vulnerabilities: ${totalVulns}`);
                this.outputChannel.appendLine(`  Secrets: ${totalSecrets}`);
                if (failedScans > 0) {
                    this.outputChannel.appendLine(`  Failed scans: ${failedScans}`);
                }
                this.outputChannel.appendLine(`${'='.repeat(50)}\n`);

                const totalIssues = totalIaCFindings + totalVulns + totalSecrets;
                // Calculate total scan targets: Terraform directories + CloudFormation files + TMAS directory scan
                // Use the filtered root directories count
                const allTfDirsForCount = new Set(iacFiles.terraform.map(f => path.dirname(f)));
                const rootTfDirs = [...allTfDirsForCount].filter(dir => {
                    let parent = path.dirname(dir);
                    let current = dir;
                    while (parent !== current && parent.startsWith(targetPath)) {
                        if (allTfDirsForCount.has(parent)) {
                            return false;
                        }
                        current = parent;
                        parent = path.dirname(current);
                    }
                    return true;
                });
                const totalScanTargets = rootTfDirs.length + iacFiles.cloudformation.length + 1;

                // Set scan summary
                this.resultsPanel.setScanSummary({
                    totalFiles: totalScanTargets,
                    successfulScans,
                    failedScans,
                    errors: [] // Errors already added individually
                });

                // Mark scanning as complete
                this.resultsPanel.setScanning(false);

                // Show appropriate message based on success/failure
                if (failedScans > 0) {
                    vscode.window.showWarningMessage(
                        `Scan complete with errors: ${totalIssues} issues found, ${failedScans} scan${failedScans > 1 ? 's' : ''} failed`
                    );
                } else {
                    vscode.window.showInformationMessage(
                        `Scan complete: ${totalIssues} issues found (${totalIaCFindings} IaC, ${totalVulns} vulns, ${totalSecrets} secrets)`
                    );
                }

                this.updateStatusBar();
            } catch (error) {
                // Mark scanning as complete even on error
                if (this.resultsPanel) {
                    this.resultsPanel.setScanning(false);
                }
                this.handleError('Scan failed', error);
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
        if (ResultsPanelProvider.currentPanel) {
            ResultsPanelProvider.currentPanel.clear();
        }
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

    private handleError(message: string, error: unknown, file?: string): void {
        // Parse error for friendly message
        const parsed = parseError(error);

        // Log detailed error to output channel
        const rawMessage = error instanceof Error ? error.message : String(error);
        this.outputChannel.appendLine(`ERROR: ${message}`);
        this.outputChannel.appendLine(`  Code: ${parsed.code}`);
        this.outputChannel.appendLine(`  Message: ${parsed.message}`);
        if (parsed.details) {
            this.outputChannel.appendLine(`  Details: ${parsed.details}`);
        }
        if (parsed.suggestion) {
            this.outputChannel.appendLine(`  Suggestion: ${parsed.suggestion}`);
        }

        // Log full error details including API response
        if (error && typeof error === 'object' && 'response' in error) {
            this.outputChannel.appendLine(`  API Response: ${JSON.stringify((error as { response: unknown }).response, null, 2)}`);
        }

        // Add error to results panel if it exists
        if (this.resultsPanel) {
            this.resultsPanel.addError(toScanError(parsed, file));
        }

        // Show user-friendly error message
        const userMessage = parsed.suggestion
            ? `${parsed.message}. ${parsed.suggestion}`
            : parsed.message;

        vscode.window.showErrorMessage(`${message}: ${userMessage}`);
    }

    /**
     * Multi-step LLM endpoint security scan workflow
     */
    async scanLLMEndpoint(): Promise<void> {
        try {
            // Step 0: Ensure prerequisites
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

            // Check for saved configs
            const savedConfigs = this.listSavedConfigs();
            if (savedConfigs.length > 0) {
                const loaded = await this.promptLoadSavedConfig(savedConfigs);
                if (loaded === 'cancel') return;
                if (loaded) {
                    // Run with loaded config - don't create new config file
                    await this.runLLMScan(loaded.config, tmasPath, loaded.configName);
                    return;
                }
                // User chose "New Scan", continue with normal flow
            }

            // Step 1: Select endpoint type
            const endpointType = await this.selectEndpointType();
            if (!endpointType) return;

            // Step 2: Enter endpoint URL
            const endpointUrl = await this.enterEndpointUrl(endpointType);
            if (!endpointUrl) return;

            // Step 3: Get API key if needed
            let targetApiKey: string | undefined;
            if (ENDPOINT_CONFIGS[endpointType].requiresApiKey) {
                targetApiKey = await this.enterTargetApiKey(endpointType);
                if (!targetApiKey) return;
            }

            // Step 4: Discover and select model
            const model = await this.discoverAndSelectModel(endpointType, endpointUrl, targetApiKey);
            if (!model) return;

            // Step 5: Select attack objectives
            const objectives = await this.selectAttackObjectives();
            if (!objectives || objectives.length === 0) return;

            // Step 6: Select attack techniques
            const techniques = await this.selectAttackTechniques();
            if (!techniques || techniques.length === 0) return;

            // Step 7: Select attack modifiers
            const modifiers = await this.selectAttackModifiers();
            if (!modifiers || modifiers.length === 0) return;

            // Step 8: Optional - Enter system prompt to test against
            const systemPrompt = await this.enterSystemPrompt();

            // Build config
            const config: LLMScanConfig = {
                endpointType,
                endpointUrl: this.normalizeEndpointUrl(endpointUrl),
                model,
                apiKey: targetApiKey,
                objectives,
                techniques,
                modifiers,
                concurrency: 2,
                systemPrompt
            };

            // Name the config
            const configName = await vscode.window.showInputBox({
                title: 'Name this scan configuration',
                prompt: 'Enter a name to save this config for reuse',
                value: `${model}-${endpointType}`,
                placeHolder: 'my-llm-scan',
                ignoreFocusOut: true
            });
            if (!configName) return;

            // Run the scan with named config
            await this.runLLMScan(config, tmasPath, configName);

        } catch (error) {
            this.handleError('LLM scan failed', error);
        }
    }

    private async selectEndpointType(): Promise<LLMEndpointType | undefined> {
        const items: vscode.QuickPickItem[] = [
            {
                label: '$(server) Ollama',
                description: 'Local Ollama instance (localhost:11434)',
                detail: 'Scan locally running Ollama models'
            },
            {
                label: '$(server) LM Studio',
                description: 'Local LM Studio server (localhost:1234)',
                detail: 'Scan locally running LM Studio models'
            },
            {
                label: '$(cloud) OpenAI',
                description: 'OpenAI API (api.openai.com)',
                detail: 'Scan OpenAI models (requires API key)'
            },
            {
                label: '$(azure) Azure OpenAI',
                description: 'Azure OpenAI Service',
                detail: 'Scan Azure-hosted models (requires API key)'
            },
            {
                label: '$(globe) Custom Endpoint',
                description: 'Any OpenAI-compatible endpoint',
                detail: 'Scan any OpenAI-compatible API'
            }
        ];

        const selected = await vscode.window.showQuickPick(items, {
            title: 'TrendAI LLM Security Scanner (Step 1/8)',
            placeHolder: 'Select your LLM endpoint type',
            ignoreFocusOut: true
        });

        if (!selected) return undefined;

        const typeMap: Record<string, LLMEndpointType> = {
            '$(server) Ollama': 'ollama',
            '$(server) LM Studio': 'lmstudio',
            '$(cloud) OpenAI': 'openai',
            '$(azure) Azure OpenAI': 'azure',
            '$(globe) Custom Endpoint': 'custom'
        };

        return typeMap[selected.label];
    }

    private async enterEndpointUrl(endpointType: LLMEndpointType): Promise<string | undefined> {
        const config = ENDPOINT_CONFIGS[endpointType];
        const defaultUrl = config.baseUrl;

        const url = await vscode.window.showInputBox({
            title: 'TrendAI LLM Security Scanner (Step 2/8)',
            prompt: `Enter the ${config.name} endpoint URL`,
            value: defaultUrl,
            placeHolder: 'e.g., http://localhost:11434 or https://api.openai.com',
            ignoreFocusOut: true,
            validateInput: (value) => {
                if (!value) return 'URL is required';
                try {
                    new URL(value);
                    return undefined;
                } catch {
                    return 'Please enter a valid URL';
                }
            }
        });

        if (!url) return undefined;

        // Check endpoint health for local endpoints
        if (endpointType === 'ollama' || endpointType === 'lmstudio') {
            const isHealthy = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Checking endpoint connectivity...',
                cancellable: false
            }, async () => {
                return await this.llmScanner.checkEndpointHealth(url);
            });

            if (!isHealthy) {
                const proceed = await vscode.window.showWarningMessage(
                    `Could not connect to ${url}. The endpoint may be offline.`,
                    'Continue Anyway',
                    'Cancel'
                );
                if (proceed !== 'Continue Anyway') return undefined;
            }
        }

        return url;
    }

    private async enterTargetApiKey(endpointType: LLMEndpointType): Promise<string | undefined> {
        const config = ENDPOINT_CONFIGS[endpointType];

        return await vscode.window.showInputBox({
            title: 'TrendAI LLM Security Scanner (Step 3/8)',
            prompt: `Enter your ${config.name} API key`,
            password: true,
            placeHolder: 'sk-...',
            ignoreFocusOut: true,
            validateInput: (value) => {
                if (!value) return 'API key is required for this endpoint type';
                return undefined;
            }
        });
    }

    private async discoverAndSelectModel(
        endpointType: LLMEndpointType,
        endpointUrl: string,
        apiKey?: string
    ): Promise<string | undefined> {
        let models: DiscoveredModel[] = [];

        // Try to discover models
        try {
            models = await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Discovering available models...',
                cancellable: false
            }, async () => {
                return await this.llmScanner.discoverModels(endpointType, endpointUrl, apiKey);
            });

            this.outputChannel.appendLine(`Discovered ${models.length} models`);
        } catch (error) {
            this.outputChannel.appendLine(`Model discovery failed: ${error}`);
            // Continue to manual entry
        }

        if (models.length === 0) {
            // No models found or discovery failed - manual entry
            return await vscode.window.showInputBox({
                title: 'TrendAI LLM Security Scanner (Step 4/8)',
                prompt: 'Enter the model name to scan',
                placeHolder: 'e.g., gpt-4, llama3.2, mistral:7b',
                ignoreFocusOut: true,
                validateInput: (value) => {
                    if (!value) return 'Model name is required';
                    return undefined;
                }
            });
        }

        if (models.length === 1) {
            // Single model - auto-select with confirmation
            const confirm = await vscode.window.showInformationMessage(
                `Found 1 model: ${models[0].name}. Use this model?`,
                'Yes',
                'Enter Different'
            );

            if (confirm === 'Yes') {
                return models[0].id;
            }

            return await vscode.window.showInputBox({
                title: 'TrendAI LLM Security Scanner (Step 4/8)',
                prompt: 'Enter the model name to scan',
                placeHolder: 'e.g., gpt-4, llama3.2, mistral:7b',
                ignoreFocusOut: true
            });
        }

        // Multiple models - let user pick
        const items: vscode.QuickPickItem[] = models.map(m => ({
            label: m.name,
            description: m.size ? `${(m.size / 1e9).toFixed(1)} GB` : undefined,
            detail: m.modified ? `Modified: ${new Date(m.modified).toLocaleDateString()}` : undefined
        }));

        // Add option for manual entry
        items.push({
            label: '$(edit) Enter custom model name...',
            description: 'Type a model name manually'
        });

        const selected = await vscode.window.showQuickPick(items, {
            title: `TrendAI LLM Security Scanner (Step 4/8) - Found ${models.length} models`,
            placeHolder: 'Select the model to scan',
            ignoreFocusOut: true
        });

        if (!selected) return undefined;

        if (selected.label === '$(edit) Enter custom model name...') {
            return await vscode.window.showInputBox({
                prompt: 'Enter the model name to scan',
                placeHolder: 'e.g., gpt-4, llama3.2, mistral:7b',
                ignoreFocusOut: true
            });
        }

        return selected.label;
    }

    private async selectAttackObjectives(): Promise<string[] | undefined> {
        const items: vscode.QuickPickItem[] = ATTACK_OBJECTIVES.map(obj => ({
            label: obj.name,
            description: obj.description,
            picked: true // All selected by default
        }));

        const selected = await vscode.window.showQuickPick(items, {
            title: 'TrendAI LLM Security Scanner (Step 5/8)',
            placeHolder: 'Select attack objectives to test',
            canPickMany: true,
            ignoreFocusOut: true
        });

        if (!selected || selected.length === 0) {
            const useDefaults = await vscode.window.showWarningMessage(
                'No objectives selected. Use all default objectives?',
                'Use All',
                'Cancel'
            );
            if (useDefaults === 'Use All') {
                return ATTACK_OBJECTIVES.map(o => o.name);
            }
            return undefined;
        }

        return selected.map(s => s.label);
    }

    private async selectAttackTechniques(): Promise<string[] | undefined> {
        const items: vscode.QuickPickItem[] = ATTACK_TECHNIQUES.map(tech => ({
            label: tech.name,
            description: tech.description,
            picked: tech.id === 'none' // Only "None" selected by default
        }));

        const selected = await vscode.window.showQuickPick(items, {
            title: 'TrendAI LLM Security Scanner (Step 6/8)',
            placeHolder: 'Select attack techniques (jailbreak methods)',
            canPickMany: true,
            ignoreFocusOut: true
        });

        if (!selected || selected.length === 0) {
            // Default to "None" if nothing selected
            return ['None'];
        }

        return selected.map(s => s.label);
    }

    private async selectAttackModifiers(): Promise<string[] | undefined> {
        const items: vscode.QuickPickItem[] = ATTACK_MODIFIERS.map(mod => ({
            label: mod.name,
            description: mod.description,
            picked: mod.id === 'none' // Only "None" selected by default
        }));

        const selected = await vscode.window.showQuickPick(items, {
            title: 'TrendAI LLM Security Scanner (Step 7/8)',
            placeHolder: 'Select attack modifiers (payload encoding)',
            canPickMany: true,
            ignoreFocusOut: true
        });

        if (!selected || selected.length === 0) {
            // Default to "None" if nothing selected
            return ['None'];
        }

        return selected.map(s => s.label);
    }

    private async enterSystemPrompt(): Promise<string | undefined> {
        const hasPrompt = await vscode.window.showQuickPick([
            { label: '$(pass) Skip', description: 'Scan without a specific system prompt' },
            { label: '$(file-text) Enter System Prompt', description: 'Test against a specific system prompt' }
        ], {
            title: 'TrendAI LLM Security Scanner (Optional)',
            placeHolder: 'Do you want to specify a system prompt to test against?'
        });

        if (hasPrompt?.label === '$(file-text) Enter System Prompt') {
            return await vscode.window.showInputBox({
                prompt: 'Enter the system prompt to test against',
                placeHolder: 'You are a helpful assistant...',
                ignoreFocusOut: true
            });
        }

        return undefined;
    }

    // ============ Saved Config Management ============

    private getSavedConfigsDir(): string {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            return path.join(workspaceFolders[0].uri.fsPath, '.trendai-scans', 'saved-configs');
        }
        return path.join(this.context.globalStorageUri.fsPath, 'saved-configs');
    }

    private getScansDir(): string {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            return path.join(workspaceFolders[0].uri.fsPath, '.trendai-scans', 'results');
        }
        return path.join(this.context.globalStorageUri.fsPath, 'llm-scans', 'results');
    }

    private listSavedConfigs(): SavedLLMConfig[] {
        const savedDir = this.getSavedConfigsDir();
        if (!fs.existsSync(savedDir)) {
            return [];
        }

        try {
            const files = fs.readdirSync(savedDir)
                .filter(f => f.endsWith('.yaml'))
                .sort()
                .reverse()
                .slice(0, 10); // Show last 10 configs

            return files.map(f => {
                const filePath = path.join(savedDir, f);
                const content = fs.readFileSync(filePath, 'utf-8');
                const parsed = yaml.load(content) as Record<string, unknown>;
                const target = parsed.target as Record<string, unknown> || {};
                const objectives = parsed.attack_objectives as Array<Record<string, unknown>> || [];
                const stats = fs.statSync(filePath);

                return {
                    name: f,
                    createdAt: stats.mtime.toISOString(),
                    config: {
                        endpointType: 'custom' as const,
                        endpointUrl: (target.endpoint as string) || '',
                        model: (target.model as string) || '',
                        objectives: objectives.map(o => o.name as string),
                        techniques: (objectives[0]?.techniques as string[]) || ['None'],
                        modifiers: (objectives[0]?.modifiers as string[]) || ['None'],
                        concurrency: (parsed.settings as Record<string, unknown>)?.concurrency as number || 2,
                        systemPrompt: (target.system_prompt as string) || undefined
                    }
                } as SavedLLMConfig;
            }).filter(c => c && c.config);
        } catch {
            return [];
        }
    }

    private async promptLoadSavedConfig(configs: SavedLLMConfig[]): Promise<{ config: LLMScanConfig, configName: string } | 'cancel' | undefined> {
        const items: vscode.QuickPickItem[] = [
            {
                label: '$(add) New Scan',
                description: 'Create a new scan configuration',
                detail: 'Configure endpoint, model, and attack options from scratch'
            }
        ];

        if (configs.length > 0) {
            items.push({ label: 'Saved Configs', kind: vscode.QuickPickItemKind.Separator });
            items.push(...configs.map((c, index) => ({
                label: `$(file) ${c.name.replace('.yaml', '')}`,
                description: `${c.config.model || 'Unknown'} - ${c.config.objectives?.length || 0} objectives`,
                detail: new Date(c.createdAt).toLocaleString(),
                index // Store index for lookup
            })));
        }

        const selected = await vscode.window.showQuickPick(items, {
            title: 'TrendAI LLM Security Scanner',
            placeHolder: 'Load a saved config or create new',
            ignoreFocusOut: true
        }) as (vscode.QuickPickItem & { index?: number }) | undefined;

        if (!selected) return 'cancel';
        if (selected.label === '$(add) New Scan') return undefined;

        // Find config by index
        if (selected.index !== undefined) {
            const savedConfig = configs[selected.index];
            if (savedConfig) {
                // Return config name without .yaml extension
                const configName = savedConfig.name.replace('.yaml', '');
                return { config: savedConfig.config, configName };
            }
        }

        return undefined;
    }


    private normalizeEndpointUrl(url: string): string {
        // Ensure URL ends with /v1 for OpenAI-compatible endpoints
        // but remove /chat/completions if user accidentally included it
        let normalized = url.replace(/\/+$/, ''); // Remove trailing slashes

        if (normalized.endsWith('/chat/completions')) {
            normalized = normalized.replace('/chat/completions', '');
        }

        // For Ollama, use /v1 endpoint for OpenAI compatibility
        if (normalized.includes(':11434') && !normalized.includes('/v1')) {
            normalized = normalized + '/v1';
        }

        // For LM Studio, ensure /v1 is present
        if (normalized.includes(':1234') && !normalized.includes('/v1')) {
            normalized = normalized + '/v1';
        }

        return normalized;
    }

    private async runLLMScan(config: LLMScanConfig, tmasPath: string, configName?: string): Promise<void> {
        await this.runWithProgress('Scanning LLM endpoint for security vulnerabilities...', async () => {
            try {
                const result = await this.llmScanner.scan(config, tmasPath, configName);

                // Show results in panel
                this.resultsPanel = ResultsPanelProvider.createOrShow(this.extensionUri);
                this.resultsPanel.addLLMResults(result);

                // Show summary notification
                const successRate = result.summary.totalSuccessful + result.summary.totalFailed > 0
                    ? Math.round((result.summary.totalSuccessful / (result.summary.totalSuccessful + result.summary.totalFailed)) * 100)
                    : 0;

                const severity = successRate >= 50 ? 'high' : successRate >= 20 ? 'medium' : 'low';
                const message = `LLM Scan Complete: ${result.summary.totalSuccessful} attacks succeeded out of ${result.details.totalTests} tests (${successRate}% vulnerable)`;

                if (severity === 'high') {
                    vscode.window.showErrorMessage(message, 'View Results').then(action => {
                        if (action === 'View Results') {
                            this.showResultsPanel();
                        }
                    });
                } else if (severity === 'medium') {
                    vscode.window.showWarningMessage(message, 'View Results').then(action => {
                        if (action === 'View Results') {
                            this.showResultsPanel();
                        }
                    });
                } else {
                    vscode.window.showInformationMessage(message, 'View Results').then(action => {
                        if (action === 'View Results') {
                            this.showResultsPanel();
                        }
                    });
                }

                this.updateStatusBar();
                this.outputChannel.appendLine(`LLM scan completed: ${result.summary.totalSuccessful}/${result.details.totalTests} attacks succeeded`);

            } catch (error) {
                throw error;
            }
        });
    }
}
