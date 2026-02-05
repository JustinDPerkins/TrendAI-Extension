import * as vscode from 'vscode';
import { SettingsManager } from './config/settings';
import { TmasScanner } from './scanners/tmas';
import { TemplateScanner } from './scanners/templateScanner';
import { DiagnosticsProvider } from './providers/diagnostics';
import { ResultsTreeProvider } from './providers/treeView';
import { SecurityCodeActionProvider } from './providers/codeActions';
import { CommandHandler } from './commands';
import { isIaCFile } from './utils/fileUtils';

let outputChannel: vscode.OutputChannel;
let settingsManager: SettingsManager;
let tmasScanner: TmasScanner;
let templateScanner: TemplateScanner;
let diagnosticsProvider: DiagnosticsProvider;
let resultsTreeProvider: ResultsTreeProvider;
let commandHandler: CommandHandler;
let statusBarItem: vscode.StatusBarItem;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    outputChannel = vscode.window.createOutputChannel('TrendAI™ Security');
    outputChannel.appendLine('TrendAI™ Security Scanner activating...');

    // Initialize settings manager
    settingsManager = new SettingsManager(context);

    // Initialize providers
    const settings = settingsManager.getSettings();
    diagnosticsProvider = new DiagnosticsProvider(settings.severityThreshold);
    resultsTreeProvider = new ResultsTreeProvider();

    // Initialize scanners
    tmasScanner = new TmasScanner(settingsManager, outputChannel);
    templateScanner = new TemplateScanner(settingsManager, outputChannel);
    await templateScanner.initialize();

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = '$(shield) TrendAI™';
    statusBarItem.tooltip = 'TrendAI™ Security Scanner';
    statusBarItem.command = 'trendmicro.scanDirectory';
    statusBarItem.show();

    // Initialize command handler
    commandHandler = new CommandHandler(
        tmasScanner,
        templateScanner,
        diagnosticsProvider,
        resultsTreeProvider,
        settingsManager,
        outputChannel,
        statusBarItem,
        context.extensionUri
    );

    // Register tree view
    const treeView = vscode.window.createTreeView('trendmicro.resultsView', {
        treeDataProvider: resultsTreeProvider,
        showCollapseAll: true
    });

    // Register code action provider
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        new SecurityCodeActionProvider(),
        { providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds }
    );

    // Register commands
    const commands = [
        vscode.commands.registerCommand('trendmicro.scanDirectory', (uri?: vscode.Uri) =>
            commandHandler.scanDirectory(uri)
        ),
        vscode.commands.registerCommand('trendmicro.scanFile', (uri?: vscode.Uri) =>
            commandHandler.scanFile(uri)
        ),
        vscode.commands.registerCommand('trendmicro.scanImage', () =>
            commandHandler.scanImage()
        ),
        vscode.commands.registerCommand('trendmicro.scanTemplate', (uri?: vscode.Uri) =>
            commandHandler.scanTemplate(uri)
        ),
        vscode.commands.registerCommand('trendmicro.scanTerraformProject', (uri?: vscode.Uri) =>
            commandHandler.scanTerraformProject(uri)
        ),
        vscode.commands.registerCommand('trendmicro.setApiToken', () =>
            commandHandler.setApiToken()
        ),
        vscode.commands.registerCommand('trendmicro.refreshResults', () =>
            commandHandler.refreshResults()
        ),
        vscode.commands.registerCommand('trendmicro.clearResults', () =>
            commandHandler.clearResults()
        ),
        vscode.commands.registerCommand('trendmicro.showVulnerabilityFix', (metadata) =>
            commandHandler.showVulnerabilityFix(metadata)
        ),
        vscode.commands.registerCommand('trendmicro.addToGitignore', (filePath: string) =>
            commandHandler.addToGitignore(filePath)
        ),
        vscode.commands.registerCommand('trendmicro.suppressFinding', (diagnostic, metadata) =>
            commandHandler.suppressFinding(diagnostic, metadata)
        ),
        vscode.commands.registerCommand('trendmicro.showResultsPanel', () =>
            commandHandler.showResultsPanel()
        ),
        vscode.commands.registerCommand('trendmicro.buildAndScanDockerfile', (uri?: vscode.Uri) =>
            commandHandler.buildAndScanDockerfile(uri)
        ),
        vscode.commands.registerCommand('trendmicro.launchAIScanner', () =>
            commandHandler.launchAIScanner()
        )
    ];

    // Register scan on save if enabled
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (!settingsManager.shouldScanOnSave()) {
            return;
        }

        const filePath = document.uri.fsPath;

        // Check if it's an IaC file for template scanning
        if (isIaCFile(filePath)) {
            try {
                const result = await templateScanner.scanFile(filePath);
                diagnosticsProvider.clearDiagnostics(document.uri);
                diagnosticsProvider.addTemplateScanResults(result, document.uri);
                resultsTreeProvider.addTemplateResult(filePath, result);
            } catch (error) {
                outputChannel.appendLine(`Scan on save failed: ${error}`);
            }
        }
    });

    // Listen for configuration changes
    const configChangeDisposable = settingsManager.onDidChangeConfiguration(async () => {
        const newSettings = settingsManager.getSettings();
        diagnosticsProvider.setSeverityThreshold(newSettings.severityThreshold);
        await templateScanner.updateCredentials();
        outputChannel.appendLine('Configuration updated');
    });

    // Add all disposables to context
    context.subscriptions.push(
        outputChannel,
        statusBarItem,
        treeView,
        codeActionProvider,
        diagnosticsProvider,
        onSaveDisposable,
        configChangeDisposable,
        ...commands
    );

    // Check for API token and prompt if not configured
    const hasToken = await settingsManager.hasApiToken();
    if (!hasToken) {
        const action = await vscode.window.showInformationMessage(
            'TrendAI™ Security Scanner: API token not configured. Configure now?',
            'Configure',
            'Later'
        );

        if (action === 'Configure') {
            await commandHandler.setApiToken();
        }
    }

    outputChannel.appendLine('TrendAI™ Security Scanner activated');
}

export function deactivate(): void {
    outputChannel?.appendLine('TrendAI™ Security Scanner deactivated');
}
