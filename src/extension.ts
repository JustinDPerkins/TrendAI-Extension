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

    try {
        // Initialize settings manager
        settingsManager = new SettingsManager(context);

    // Initialize providers
    const settings = settingsManager.getSettings();
    diagnosticsProvider = new DiagnosticsProvider(settings.severityThreshold);
    resultsTreeProvider = new ResultsTreeProvider();

    // Initialize scanners
    tmasScanner = new TmasScanner(settingsManager, outputChannel);
    templateScanner = new TemplateScanner(settingsManager, outputChannel);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = '$(shield) TrendAI™';
    statusBarItem.tooltip = 'TrendAI™ Security Scanner';
    statusBarItem.command = 'trendai.scan';
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
        context.extensionUri,
        context
    );

    // Register tree view
    const treeView = vscode.window.createTreeView('trendai.resultsView', {
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
        // Primary scan commands
        vscode.commands.registerCommand('trendai.scan', (uri?: vscode.Uri) =>
            commandHandler.scan(uri)
        ),
        vscode.commands.registerCommand('trendai.scanLLMEndpoint', () =>
            commandHandler.scanLLMEndpoint()
        ),
        vscode.commands.registerCommand('trendai.buildAndScanDockerfile', (uri?: vscode.Uri) =>
            commandHandler.buildAndScanDockerfile(uri)
        ),
        // Configuration
        vscode.commands.registerCommand('trendai.setApiToken', () =>
            commandHandler.setApiToken()
        ),
        // Results management
        vscode.commands.registerCommand('trendai.showResultsPanel', () =>
            commandHandler.showResultsPanel()
        ),
        vscode.commands.registerCommand('trendai.refreshResults', () =>
            commandHandler.refreshResults()
        ),
        vscode.commands.registerCommand('trendai.clearResults', () =>
            commandHandler.clearResults()
        ),
        // Quick fixes
        vscode.commands.registerCommand('trendai.showVulnerabilityFix', (metadata) =>
            commandHandler.showVulnerabilityFix(metadata)
        ),
        vscode.commands.registerCommand('trendai.addToGitignore', (filePath: string) =>
            commandHandler.addToGitignore(filePath)
        ),
        vscode.commands.registerCommand('trendai.suppressFinding', (diagnostic, metadata) =>
            commandHandler.suppressFinding(diagnostic, metadata)
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

    // Initialize template scanner (non-blocking)
    templateScanner.initialize().catch(err => {
        outputChannel.appendLine(`Template scanner initialization warning: ${err}`);
    });

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
    } catch (error) {
        outputChannel.appendLine(`Activation error: ${error}`);
        vscode.window.showErrorMessage(`TrendAI™ Security Scanner failed to activate: ${error}`);
    }
}

export function deactivate(): void {
    outputChannel?.appendLine('TrendAI™ Security Scanner deactivated');
}
