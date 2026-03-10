import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { SettingsManager } from '../config/settings';
import { getPlatformInfo, ensureDirectory, makeExecutable, downloadFile, fileExists } from '../utils/fileUtils';

// TMAS scan result types
export interface TmasVulnerability {
    id: string;
    name: string;
    type?: string;
    version?: string;
    severity: string;
    source?: string;
    fix?: string;
    locations?: string[];
    title?: string;
    description?: string;
    fixedVersion?: string;
    installedVersion?: string;
    packageName?: string;
    packageType?: string;
    cvssSeverity?: string;
    cvssScore?: number;
    exploitAvailable?: boolean;
    link?: string;
}

// Helper to flatten grouped findings into array
export function flattenFindings<T>(findings: T[] | Record<string, T[]> | Record<string, never> | undefined): T[] {
    if (!findings) return [];
    if (Array.isArray(findings)) return findings;
    if (typeof findings === 'object') {
        const result: T[] = [];
        for (const key of Object.keys(findings)) {
            const group = (findings as Record<string, T[]>)[key];
            if (Array.isArray(group)) {
                result.push(...group);
            }
        }
        return result;
    }
    return [];
}

export interface TmasSecret {
    ruleID: string;
    description?: string;
    startLine?: number;
    endLine?: number;
    startColumn?: number;
    endColumn?: number;
    file?: string;
    match?: string;
    secret?: string;
    entropy?: number;
}

export interface TmasMalware {
    fileName?: string;
    foundMalwares?: Array<{
        malwareName: string;
        fileSHA256?: string;
    }>;
}

export interface TmasScanResult {
    vulnerabilities?: {
        totalVulnCount?: number;
        criticalCount?: number;
        highCount?: number;
        mediumCount?: number;
        lowCount?: number;
        negligibleCount?: number;
        unknownCount?: number;
        overriddenCount?: number;
        findings?: TmasVulnerability[] | Record<string, never>;
    };
    secrets?: {
        totalSecretCount?: number;
        totalFilesScanned?: number;
        unmitigatedFindingsCount?: number;
        overriddenFindingsCount?: number;
        findings?: TmasSecret[] | Record<string, never>;
    };
    malware?: {
        scanResult?: number;
        findings?: TmasMalware[] | Record<string, never>;
    };
    scanStartedAt?: string;
    scanCompletedAt?: string;
    artifactType?: string;
    artifactName?: string;
}

export type ArtifactType =
    | 'dir'
    | 'file'
    | 'registry'
    | 'docker'
    | 'podman'
    | 'docker-archive'
    | 'oci-archive'
    | 'oci-dir'
    | 'singularity';

export interface ScanOptions {
    artifactType: ArtifactType;
    target: string;
    includeVulnerabilities?: boolean;
    includeMalware?: boolean;
    includeSecrets?: boolean;
    region?: string;
    evaluatePolicy?: boolean;
    redacted?: boolean;
}

const TMAS_DOWNLOAD_URLS: Record<string, Record<string, string>> = {
    'darwin': {
        'arm64': 'https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Darwin_arm64.zip',
        'x86_64': 'https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Darwin_x86_64.zip'
    },
    'linux': {
        'arm64': 'https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Linux_arm64.tar.gz',
        'x86_64': 'https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Linux_x86_64.tar.gz'
    },
    'win32': {
        'arm64': 'https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Windows_arm64.zip',
        'x86_64': 'https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Windows_x86_64.zip'
    }
};

export class TmasScanner {
    private settingsManager: SettingsManager;
    private outputChannel: vscode.OutputChannel;

    constructor(settingsManager: SettingsManager, outputChannel: vscode.OutputChannel) {
        this.settingsManager = settingsManager;
        this.outputChannel = outputChannel;
    }

    private getResultsDir(): string {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            return path.join(workspaceFolders[0].uri.fsPath, '.trendai-scans', 'results');
        }
        return path.join(process.env.HOME || '/tmp', '.trendai-scans', 'results');
    }

    private saveResults(result: TmasScanResult, scanType: string, target: string): string {
        const resultsDir = this.getResultsDir();
        if (!fs.existsSync(resultsDir)) {
            fs.mkdirSync(resultsDir, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const targetName = path.basename(target).replace(/[^a-zA-Z0-9-_]/g, '_');
        const filename = `iac-scan-${targetName}-${timestamp}.json`;
        const filePath = path.join(resultsDir, filename);

        const scanRecord = {
            scanType,
            target,
            timestamp: new Date().toISOString(),
            result
        };

        fs.writeFileSync(filePath, JSON.stringify(scanRecord, null, 2));
        this.outputChannel.appendLine(`Results saved to: ${filePath}`);
        return filePath;
    }

    async ensureTmasInstalled(): Promise<string> {
        const tmasPath = this.settingsManager.getTmasPath();

        if (fileExists(tmasPath)) {
            return tmasPath;
        }

        // Check if user has set a custom path that doesn't exist
        const settings = this.settingsManager.getSettings();
        if (settings.tmasPath && !fileExists(settings.tmasPath)) {
            throw new Error(`TMAS binary not found at configured path: ${settings.tmasPath}`);
        }

        // Auto-download TMAS
        return await this.downloadTmas();
    }

    private async downloadTmas(): Promise<string> {
        const { platform, arch } = getPlatformInfo();
        const platformKey = platform as string;

        this.outputChannel.appendLine(`Detected platform: ${platform}, architecture: ${arch}`);

        if (!TMAS_DOWNLOAD_URLS[platformKey]) {
            throw new Error(`Unsupported platform: ${platform}. Supported: darwin (macOS), linux, win32 (Windows)`);
        }

        const downloadUrl = TMAS_DOWNLOAD_URLS[platformKey][arch];
        if (!downloadUrl) {
            throw new Error(`Unsupported architecture for ${platform}: ${arch}. Supported: amd64, arm64`);
        }

        this.outputChannel.appendLine(`Download URL: ${downloadUrl}`);

        const tmasPath = this.settingsManager.getDefaultTmasPath();
        const binDir = path.dirname(tmasPath);
        ensureDirectory(binDir);

        const isZip = downloadUrl.endsWith('.zip');
        const tempFile = path.join(binDir, isZip ? 'tmas-download.zip' : 'tmas-download.tar.gz');

        this.outputChannel.appendLine(`Downloading TMAS from ${downloadUrl}...`);

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Downloading TMAS binary...',
            cancellable: false
        }, async () => {
            await downloadFile(downloadUrl, tempFile);
            await this.extractArchive(tempFile, binDir, isZip);

            // Clean up temp file
            if (fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
            }
        });

        if (!fileExists(tmasPath)) {
            throw new Error('Failed to extract TMAS binary');
        }

        makeExecutable(tmasPath);
        this.outputChannel.appendLine(`TMAS installed to ${tmasPath}`);

        return tmasPath;
    }

    private async extractArchive(archivePath: string, destDir: string, isZip: boolean): Promise<void> {
        return new Promise((resolve, reject) => {
            let command: string;
            const isWindows = process.platform === 'win32';

            if (isZip) {
                if (isWindows) {
                    // Use PowerShell's Expand-Archive on Windows
                    command = `powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${destDir}' -Force"`;
                } else {
                    command = `unzip -o "${archivePath}" -d "${destDir}"`;
                }
            } else {
                // tar is available on Windows 10+ and all Unix systems
                command = `tar -xzf "${archivePath}" -C "${destDir}"`;
            }

            cp.exec(command, (error) => {
                if (error) {
                    reject(new Error(`Failed to extract archive: ${error.message}`));
                } else {
                    resolve();
                }
            });
        });
    }

    async scan(options: ScanOptions): Promise<TmasScanResult> {
        const tmasPath = await this.ensureTmasInstalled();
        const apiToken = await this.settingsManager.getApiToken();

        if (!apiToken) {
            throw new Error('API token not configured. Please set your Vision One API token.');
        }

        const args = this.buildScanArgs(options);

        this.outputChannel.appendLine(`Running: tmas ${args.join(' ')}`);

        return new Promise((resolve, reject) => {
            const env = {
                ...process.env,
                TMAS_API_KEY: apiToken
            };

            const proc = cp.spawn(tmasPath, args, { env });
            let stdout = '';
            let stderr = '';

            proc.stdout.on('data', (data: Buffer) => {
                stdout += data.toString();
            });

            proc.stderr.on('data', (data: Buffer) => {
                stderr += data.toString();
                this.outputChannel.appendLine(data.toString());
            });

            proc.on('close', (code) => {
                if (code !== 0 && code !== 2) { // 2 = policy violation, still valid output
                    reject(new Error(`TMAS scan failed (exit code ${code}): ${stderr}`));
                    return;
                }

                try {
                    this.outputChannel.appendLine(`TMAS raw output: ${stdout.substring(0, 2000)}`);
                    const result = this.parseOutput(stdout);
                    this.outputChannel.appendLine(`Parsed result keys: ${JSON.stringify(Object.keys(result))}`);

                    // Save results to disk
                    this.saveResults(result, options.artifactType, options.target);

                    resolve(result);
                } catch (parseError) {
                    this.outputChannel.appendLine(`Raw output: ${stdout}`);
                    reject(new Error(`Failed to parse TMAS output: ${parseError}`));
                }
            });

            proc.on('error', (err) => {
                reject(new Error(`Failed to run TMAS: ${err.message}`));
            });
        });
    }

    private buildScanArgs(options: ScanOptions): string[] {
        const args: string[] = ['scan'];

        // Artifact specification (trim whitespace from target)
        args.push(`${options.artifactType}:${options.target.trim()}`);

        // Scanner flags
        if (options.includeVulnerabilities !== false) {
            args.push('-V');
        }
        if (options.includeMalware) {
            args.push('-M');
        }
        if (options.includeSecrets !== false) {
            args.push('-S');
        }

        // Region
        const settings = this.settingsManager.getSettings();
        args.push('-r', options.region || settings.tmasRegion);

        // Policy evaluation
        if (options.evaluatePolicy) {
            args.push('--evaluatePolicy');
        }

        // Redact secrets
        if (options.redacted) {
            args.push('--redacted');
        }

        // TMAS outputs JSON by default, no flag needed

        return args;
    }

    private parseOutput(output: string): TmasScanResult {
        // Find the JSON object in the output (may have other text before/after)
        const jsonMatch = output.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            // Empty result is valid
            return {};
        }

        const result = JSON.parse(jsonMatch[0]);
        return this.filterExcludedPaths(result);
    }

    // Directories to exclude from scan results (downloaded dependencies, not user code)
    private static readonly EXCLUDED_PATHS = [
        '.terraform',
        'node_modules',
        '.git',
        '__pycache__',
        '.venv',
        'venv',
        '.tox',
        'dist',
        'build',
        '.eggs',
        '*.egg-info'
    ];

    private filterExcludedPaths(result: TmasScanResult): TmasScanResult {
        const shouldExclude = (filePath: string | undefined): boolean => {
            if (!filePath) return false;
            return TmasScanner.EXCLUDED_PATHS.some(excluded =>
                filePath.includes(`/${excluded}/`) ||
                filePath.includes(`\\${excluded}\\`) ||
                filePath.includes(`/.${excluded}/`)
            );
        };

        // Filter vulnerabilities - check locations array in each finding
        if (result.vulnerabilities?.findings) {
            const findings = result.vulnerabilities.findings as Record<string, Array<{ locations?: string[] }>>;
            if (typeof findings === 'object') {
                for (const severity of Object.keys(findings)) {
                    const severityFindings = findings[severity];
                    if (Array.isArray(severityFindings)) {
                        findings[severity] = severityFindings.filter(vuln => {
                            const locations = vuln.locations || [];
                            return !locations.some(loc => shouldExclude(loc));
                        });
                    }
                }
                // Recalculate counts
                let total = 0, critical = 0, high = 0, medium = 0, low = 0;
                for (const severity of Object.keys(findings)) {
                    const arr = findings[severity];
                    if (Array.isArray(arr)) {
                        const count = arr.length;
                        total += count;
                        if (severity === 'Critical') critical = count;
                        else if (severity === 'High') high = count;
                        else if (severity === 'Medium') medium = count;
                        else if (severity === 'Low') low = count;
                    }
                }
                result.vulnerabilities.totalVulnCount = total;
                result.vulnerabilities.criticalCount = critical;
                result.vulnerabilities.highCount = high;
                result.vulnerabilities.mediumCount = medium;
                result.vulnerabilities.lowCount = low;
            }
        }

        // Filter secrets
        if (result.secrets?.findings) {
            const findings = result.secrets.findings as Record<string, TmasSecret[]> | TmasSecret[];
            if (Array.isArray(findings)) {
                result.secrets.findings = findings.filter(s => !shouldExclude(s.file));
            } else if (typeof findings === 'object') {
                for (const key of Object.keys(findings)) {
                    const severityFindings = (findings as Record<string, TmasSecret[]>)[key];
                    if (Array.isArray(severityFindings)) {
                        (findings as Record<string, TmasSecret[]>)[key] = severityFindings.filter(
                            secret => !shouldExclude(secret.file)
                        );
                    }
                }
            }
        }

        return result;
    }

    async scanDirectory(dirPath: string): Promise<TmasScanResult> {
        const settings = this.settingsManager.getSettings();
        return this.scan({
            artifactType: 'dir',
            target: dirPath,
            includeVulnerabilities: settings.enableVulnerabilities,
            includeMalware: false, // Malware scanning not supported for directories
            includeSecrets: settings.enableSecrets
        });
    }

    async scanFile(filePath: string): Promise<TmasScanResult> {
        const settings = this.settingsManager.getSettings();
        return this.scan({
            artifactType: 'file',
            target: filePath,
            includeVulnerabilities: settings.enableVulnerabilities,
            includeMalware: false, // Malware scanning not supported for files
            includeSecrets: settings.enableSecrets
        });
    }

    async scanImage(imageRef: string, type: 'registry' | 'docker' | 'docker-archive' = 'registry'): Promise<TmasScanResult> {
        const settings = this.settingsManager.getSettings();
        return this.scan({
            artifactType: type,
            target: imageRef,
            includeVulnerabilities: settings.enableVulnerabilities,
            includeMalware: settings.enableMalware,
            includeSecrets: settings.enableSecrets
        });
    }

    async getVersion(): Promise<string> {
        const tmasPath = await this.ensureTmasInstalled();

        return new Promise((resolve, reject) => {
            cp.exec(`"${tmasPath}" version`, (error, stdout) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout.trim());
                }
            });
        });
    }
}
