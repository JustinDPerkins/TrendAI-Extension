import * as vscode from 'vscode';

const EXTENSION_ID = 'trendai';
const SECRET_KEY_API_TOKEN = 'trendai.apiToken';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'negligible';

export interface TrendAISettings {
    visionOneRegion: string;
    tmasPath: string;
    scanOnSave: boolean;
    severityThreshold: SeverityLevel;
    enableVulnerabilities: boolean;
    enableMalware: boolean;
    enableSecrets: boolean;
    tmasRegion: string;
}

export class SettingsManager {
    private context: vscode.ExtensionContext;
    private secretStorage: vscode.SecretStorage;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.secretStorage = context.secrets;
    }

    private getConfig(): vscode.WorkspaceConfiguration {
        return vscode.workspace.getConfiguration(EXTENSION_ID);
    }

    getSettings(): TrendAISettings {
        const config = this.getConfig();
        return {
            visionOneRegion: config.get<string>('visionOneRegion', 'api.xdr.trendmicro.com'),
            tmasPath: config.get<string>('tmasPath', ''),
            scanOnSave: config.get<boolean>('scanOnSave', false),
            severityThreshold: config.get<SeverityLevel>('severityThreshold', 'medium'),
            enableVulnerabilities: config.get<boolean>('enableVulnerabilities', true),
            enableMalware: config.get<boolean>('enableMalware', true),
            enableSecrets: config.get<boolean>('enableSecrets', true),
            tmasRegion: config.get<string>('tmasRegion', 'us-east-1')
        };
    }

    async getApiToken(): Promise<string | undefined> {
        return await this.secretStorage.get(SECRET_KEY_API_TOKEN);
    }

    async setApiToken(token: string): Promise<void> {
        await this.secretStorage.store(SECRET_KEY_API_TOKEN, token);
    }

    async deleteApiToken(): Promise<void> {
        await this.secretStorage.delete(SECRET_KEY_API_TOKEN);
    }

    async hasApiToken(): Promise<boolean> {
        const token = await this.getApiToken();
        return token !== undefined && token.length > 0;
    }

    async updateSetting<K extends keyof TrendAISettings>(
        key: K,
        value: TrendAISettings[K],
        target: vscode.ConfigurationTarget = vscode.ConfigurationTarget.Global
    ): Promise<void> {
        const config = this.getConfig();
        await config.update(key, value, target);
    }

    getTmasPath(): string {
        const settings = this.getSettings();
        if (settings.tmasPath) {
            return settings.tmasPath;
        }
        // Default path in extension's global storage
        return this.getDefaultTmasPath();
    }

    getDefaultTmasPath(): string {
        const platform = process.platform;
        const binaryName = platform === 'win32' ? 'tmas.exe' : 'tmas';
        return vscode.Uri.joinPath(this.context.globalStorageUri, 'bin', binaryName).fsPath;
    }

    getSeverityThreshold(): SeverityLevel {
        return this.getSettings().severityThreshold;
    }

    shouldScanOnSave(): boolean {
        return this.getSettings().scanOnSave;
    }

    getTmasScanFlags(): string[] {
        const settings = this.getSettings();
        const flags: string[] = [];

        if (settings.enableVulnerabilities) {
            flags.push('-V');
        }
        if (settings.enableSecrets) {
            flags.push('-S');
        }
        // Malware flag is only added for image scans (handled in scanner)

        return flags;
    }

    getTmasImageScanFlags(): string[] {
        const settings = this.getSettings();
        const flags: string[] = [];

        if (settings.enableVulnerabilities) {
            flags.push('-V');
        }
        if (settings.enableMalware) {
            flags.push('-M');
        }
        if (settings.enableSecrets) {
            flags.push('-S');
        }

        return flags;
    }

    onDidChangeConfiguration(callback: (e: vscode.ConfigurationChangeEvent) => void): vscode.Disposable {
        return vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration(EXTENSION_ID)) {
                callback(e);
            }
        });
    }

    async validateSettings(): Promise<string[]> {
        const errors: string[] = [];
        const hasToken = await this.hasApiToken();

        if (!hasToken) {
            errors.push('API token is not configured. Use "TrendAI: Set API Token" command.');
        }

        return errors;
    }

    async promptForApiToken(): Promise<boolean> {
        const token = await vscode.window.showInputBox({
            prompt: 'Enter your Vision One API Token',
            password: true,
            ignoreFocusOut: true,
            placeHolder: 'Paste your API token here'
        });

        if (token) {
            await this.setApiToken(token);
            vscode.window.showInformationMessage('API token saved successfully.');
            return true;
        }

        return false;
    }
}

export function severityToNumber(severity: string): number {
    const map: Record<string, number> = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'negligible': 1,
        'unknown': 0
    };
    return map[severity.toLowerCase()] ?? 0;
}

export function meetsThreshold(severity: string, threshold: SeverityLevel): boolean {
    return severityToNumber(severity) >= severityToNumber(threshold);
}
