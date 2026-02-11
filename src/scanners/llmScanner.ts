import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import { SettingsManager } from '../config/settings';

// LLM Endpoint Types
export type LLMEndpointType = 'ollama' | 'lmstudio' | 'openai' | 'azure' | 'custom';

export interface LLMEndpointConfig {
    type: LLMEndpointType;
    name: string;
    baseUrl: string;
    defaultPort: number;
    modelsPath: string;
    requiresApiKey: boolean;
}

export const ENDPOINT_CONFIGS: Record<LLMEndpointType, LLMEndpointConfig> = {
    ollama: {
        type: 'ollama',
        name: 'Ollama',
        baseUrl: 'http://localhost:11434',
        defaultPort: 11434,
        modelsPath: '/api/tags',
        requiresApiKey: false
    },
    lmstudio: {
        type: 'lmstudio',
        name: 'LM Studio',
        baseUrl: 'http://localhost:1234',
        defaultPort: 1234,
        modelsPath: '/v1/models',
        requiresApiKey: false
    },
    openai: {
        type: 'openai',
        name: 'OpenAI',
        baseUrl: 'https://api.openai.com',
        defaultPort: 443,
        modelsPath: '/v1/models',
        requiresApiKey: true
    },
    azure: {
        type: 'azure',
        name: 'Azure OpenAI',
        baseUrl: '',
        defaultPort: 443,
        modelsPath: '/openai/deployments',
        requiresApiKey: true
    },
    custom: {
        type: 'custom',
        name: 'Custom Endpoint',
        baseUrl: '',
        defaultPort: 443,
        modelsPath: '/v1/models',
        requiresApiKey: false
    }
};

// Attack Objectives
export interface AttackObjective {
    id: string;
    name: string;
    description: string;
    techniques: string[];
    modifiers: string[];
}

export const ATTACK_OBJECTIVES: AttackObjective[] = [
    {
        id: 'system_prompt_leakage',
        name: 'System Prompt Leakage',
        description: 'Test if attacker can extract the system prompt',
        techniques: ['None'],
        modifiers: ['None']
    },
    {
        id: 'sensitive_data_disclosure',
        name: 'Sensitive Data Disclosure',
        description: 'Test if attacker can extract PII or sensitive information',
        techniques: ['None'],
        modifiers: ['None']
    },
    {
        id: 'tool_definition_leakage',
        name: 'Agent Tool Definition Leakage',
        description: 'Test if attacker can discover available tools/functions',
        techniques: ['None'],
        modifiers: ['None']
    },
    {
        id: 'malicious_code_generation',
        name: 'Malicious Code Generation',
        description: 'Test if attacker can generate harmful code',
        techniques: ['None'],
        modifiers: ['None']
    }
];

export const ATTACK_TECHNIQUES = [
    { id: 'none', name: 'None', description: 'Baseline - no special technique' },
    { id: 'ignore_instructions', name: 'Ignore all previous instructions', description: 'Direct instruction override' },
    { id: 'dan', name: 'DAN (Do Anything Now)', description: 'Jailbreak technique' },
    { id: 'encrypt_response', name: 'Encrypt the response', description: 'Obfuscation technique' },
    { id: 'payload_splitting', name: 'Payload splitting', description: 'Split attack across messages' }
];

// LLM Scan Result Types
export interface LLMScanDetails {
    scanId: string;
    endpoint: string;
    model: string;
    scanTime: string;
    scanDuration: string;
    totalTests: number;
    region: string;
}

export interface LLMAttackResult {
    objective: string;
    technique: string;
    modifier: string;
    outcome: 'Attack Succeeded' | 'Attack Failed';
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    attackPrompt: string;
    modelResponse: string;
    evaluation: string;
}

export interface LLMScanResult {
    details: LLMScanDetails;
    results: LLMAttackResult[];
    summary: {
        totalSuccessful: number;
        totalFailed: number;
        byObjective: Record<string, { successful: number; failed: number }>;
    };
}

export interface LLMScanConfig {
    endpointType: LLMEndpointType;
    endpointUrl: string;
    model: string;
    apiKey?: string;
    objectives: string[];
    techniques: string[];
    modifiers: string[];
    concurrency: number;
    systemPrompt?: string;
}

export interface DiscoveredModel {
    id: string;
    name: string;
    modified?: string;
    size?: number;
}

export class LLMScanner {
    private settingsManager: SettingsManager;
    private outputChannel: vscode.OutputChannel;
    private context: vscode.ExtensionContext;

    constructor(
        settingsManager: SettingsManager,
        outputChannel: vscode.OutputChannel,
        context: vscode.ExtensionContext
    ) {
        this.settingsManager = settingsManager;
        this.outputChannel = outputChannel;
        this.context = context;
    }

    /**
     * Discover available models from an endpoint
     */
    async discoverModels(endpointType: LLMEndpointType, endpointUrl: string, apiKey?: string): Promise<DiscoveredModel[]> {
        const config = ENDPOINT_CONFIGS[endpointType];

        try {
            const url = new URL(config.modelsPath, endpointUrl);
            this.outputChannel.appendLine(`Discovering models from: ${url.toString()}`);

            const response = await this.httpRequest(url.toString(), apiKey);
            const data = JSON.parse(response);

            // Parse response based on endpoint type
            if (endpointType === 'ollama') {
                // Ollama returns { models: [{ name, modified_at, size }] }
                return (data.models || []).map((m: { name: string; modified_at?: string; size?: number }) => ({
                    id: m.name,
                    name: m.name,
                    modified: m.modified_at,
                    size: m.size
                }));
            } else {
                // OpenAI-compatible: { data: [{ id, object, owned_by }] }
                return (data.data || []).map((m: { id: string }) => ({
                    id: m.id,
                    name: m.id
                }));
            }
        } catch (error) {
            this.outputChannel.appendLine(`Failed to discover models: ${error}`);
            throw new Error(`Failed to discover models from ${endpointUrl}: ${error}`);
        }
    }

    /**
     * Check if an endpoint is reachable
     */
    async checkEndpointHealth(endpointUrl: string): Promise<boolean> {
        try {
            const url = new URL(endpointUrl);
            await this.httpRequest(url.toString(), undefined, 5000);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generate YAML config for TMAS aiscan
     */
    generateConfig(config: LLMScanConfig): string {
        const objectives = config.objectives.map(objName => {
            const obj = ATTACK_OBJECTIVES.find(o => o.name === objName);
            return {
                name: objName,
                description: obj?.description || '',
                techniques: config.techniques,
                modifiers: config.modifiers
            };
        });

        const yamlConfig: Record<string, unknown> = {
            version: '1.0.0',
            name: 'LLM Security Scan',
            description: `Security scan for ${config.model} at ${config.endpointUrl}`,
            target: {
                name: 'target-llm',
                endpoint: config.endpointUrl,
                model: config.model,
                type: 'openai',
                temperature: 0.0,
                system_prompt: config.systemPrompt || ''
            },
            settings: {
                concurrency: config.concurrency
            },
            attack_objectives: objectives
        };

        // Add API key reference if needed
        if (config.apiKey) {
            (yamlConfig.target as Record<string, unknown>).api_key_env = 'TARGET_API_KEY';
        }

        return this.toYaml(yamlConfig);
    }

    /**
     * Run the LLM security scan
     */
    async scan(config: LLMScanConfig, tmasPath: string): Promise<LLMScanResult> {
        const apiToken = await this.settingsManager.getApiToken();
        if (!apiToken) {
            throw new Error('TMAS API token not configured');
        }

        // Create config file
        const scanDir = this.getScanHistoryDir();
        if (!fs.existsSync(scanDir)) {
            fs.mkdirSync(scanDir, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const configPath = path.join(scanDir, `llm-config-${timestamp}.yaml`);
        const outputPath = path.join(scanDir, `llm-scan-${timestamp}.json`);

        const yamlConfig = this.generateConfig(config);
        fs.writeFileSync(configPath, yamlConfig);
        this.outputChannel.appendLine(`Config written to: ${configPath}`);
        this.outputChannel.appendLine(`Config contents:\n${yamlConfig}`);

        // Build command args
        const settings = this.settingsManager.getSettings();
        const args = [
            'aiscan', 'llm',
            '-c', configPath,
            '-r', settings.tmasRegion,
            '--output', 'json'
        ];

        this.outputChannel.appendLine(`Running: tmas ${args.join(' ')}`);

        return new Promise((resolve, reject) => {
            const env: NodeJS.ProcessEnv = {
                ...process.env,
                TMAS_API_KEY: apiToken
            };

            // Add target API key if provided
            if (config.apiKey) {
                env.TARGET_API_KEY = config.apiKey;
            }

            const proc = cp.spawn(tmasPath, args, { env });
            let stdout = '';
            let stderr = '';

            proc.stdout.on('data', (data: Buffer) => {
                stdout += data.toString();
                this.outputChannel.appendLine(data.toString());
            });

            proc.stderr.on('data', (data: Buffer) => {
                stderr += data.toString();
                this.outputChannel.appendLine(data.toString());
            });

            proc.on('close', (code) => {
                // Save raw output
                fs.writeFileSync(outputPath, stdout);
                this.outputChannel.appendLine(`Results saved to: ${outputPath}`);

                if (code !== 0 && code !== 2) {
                    reject(new Error(`TMAS scan failed (exit code ${code}): ${stderr}`));
                    return;
                }

                try {
                    const result = this.parseResults(stdout, config);
                    resolve(result);
                } catch (parseError) {
                    reject(new Error(`Failed to parse scan results: ${parseError}`));
                }
            });

            proc.on('error', (err) => {
                reject(new Error(`Failed to run TMAS: ${err.message}`));
            });
        });
    }

    /**
     * Parse TMAS JSON output into structured results
     */
    private parseResults(output: string, config: LLMScanConfig): LLMScanResult {
        // Find JSON in output
        const jsonMatch = output.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            // Return empty result if no JSON found
            return this.createEmptyResult(config);
        }

        const data = JSON.parse(jsonMatch[0]);
        const results: LLMAttackResult[] = [];

        // Parse evaluation_results array
        const evaluationResults = data.evaluation_results || [];
        for (const result of evaluationResults) {
            results.push({
                objective: result.attack_objective || 'Unknown',
                technique: result.technique || 'None',
                modifier: result.modifier || 'None',
                outcome: result.attack_outcome || 'Attack Failed',
                severity: result.severity,
                attackPrompt: result.chat_history?.[0]?.content || '',
                modelResponse: result.chat_history?.[1]?.content || '',
                evaluation: result.evaluation || ''
            });
        }

        // Calculate summary
        const summary = this.calculateSummary(results);

        return {
            details: {
                scanId: data.details?.scan_id || `scan-${Date.now()}`,
                endpoint: config.endpointUrl,
                model: config.model,
                scanTime: data.details?.scan_time || new Date().toISOString(),
                scanDuration: data.details?.scan_duration || 'N/A',
                totalTests: results.length,
                region: this.settingsManager.getSettings().tmasRegion
            },
            results,
            summary
        };
    }

    private createEmptyResult(config: LLMScanConfig): LLMScanResult {
        return {
            details: {
                scanId: `scan-${Date.now()}`,
                endpoint: config.endpointUrl,
                model: config.model,
                scanTime: new Date().toISOString(),
                scanDuration: 'N/A',
                totalTests: 0,
                region: this.settingsManager.getSettings().tmasRegion
            },
            results: [],
            summary: {
                totalSuccessful: 0,
                totalFailed: 0,
                byObjective: {}
            }
        };
    }

    private calculateSummary(results: LLMAttackResult[]): LLMScanResult['summary'] {
        const byObjective: Record<string, { successful: number; failed: number }> = {};
        let totalSuccessful = 0;
        let totalFailed = 0;

        for (const result of results) {
            const obj = result.objective;
            if (!byObjective[obj]) {
                byObjective[obj] = { successful: 0, failed: 0 };
            }

            if (result.outcome === 'Attack Succeeded') {
                byObjective[obj].successful++;
                totalSuccessful++;
            } else {
                byObjective[obj].failed++;
                totalFailed++;
            }
        }

        return { totalSuccessful, totalFailed, byObjective };
    }

    /**
     * Get previous scans for drift comparison
     */
    getPreviousScans(limit: number = 5): string[] {
        const scanDir = this.getScanHistoryDir();
        if (!fs.existsSync(scanDir)) {
            return [];
        }

        const files = fs.readdirSync(scanDir)
            .filter(f => f.startsWith('llm-scan-') && f.endsWith('.json'))
            .sort()
            .reverse()
            .slice(0, limit);

        return files.map(f => path.join(scanDir, f));
    }

    /**
     * Load a previous scan result
     */
    loadScanResult(filePath: string): LLMScanResult | null {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const data = JSON.parse(content);
            // Re-parse through our parser to ensure consistent structure
            return data;
        } catch {
            return null;
        }
    }

    private getScanHistoryDir(): string {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            return path.join(workspaceFolders[0].uri.fsPath, '.trendai-scans');
        }
        return path.join(this.context.globalStorageUri.fsPath, 'llm-scans');
    }

    private async httpRequest(url: string, apiKey?: string, timeout: number = 10000): Promise<string> {
        return new Promise((resolve, reject) => {
            const parsedUrl = new URL(url);
            const isHttps = parsedUrl.protocol === 'https:';
            const lib = isHttps ? https : http;

            const options: http.RequestOptions = {
                hostname: parsedUrl.hostname,
                port: parsedUrl.port || (isHttps ? 443 : 80),
                path: parsedUrl.pathname + parsedUrl.search,
                method: 'GET',
                timeout,
                headers: {
                    'Accept': 'application/json'
                }
            };

            if (apiKey) {
                options.headers = {
                    ...options.headers,
                    'Authorization': `Bearer ${apiKey}`
                };
            }

            const req = lib.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(data);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            req.end();
        });
    }

    private toYaml(obj: unknown, indent: number = 0): string {
        const spaces = '  '.repeat(indent);
        let yaml = '';

        if (Array.isArray(obj)) {
            for (const item of obj) {
                if (typeof item === 'object' && item !== null) {
                    yaml += `${spaces}-\n`;
                    const itemYaml = this.toYaml(item, indent + 1);
                    yaml += itemYaml;
                } else {
                    yaml += `${spaces}- ${this.yamlValue(item)}\n`;
                }
            }
        } else if (typeof obj === 'object' && obj !== null) {
            for (const [key, value] of Object.entries(obj)) {
                if (typeof value === 'object' && value !== null) {
                    yaml += `${spaces}${key}:\n`;
                    yaml += this.toYaml(value, indent + 1);
                } else {
                    yaml += `${spaces}${key}: ${this.yamlValue(value)}\n`;
                }
            }
        }

        return yaml;
    }

    private yamlValue(value: unknown): string {
        if (value === null || value === undefined) {
            return '""';
        }
        if (typeof value === 'string') {
            // Quote strings that might be interpreted as special YAML values
            if (value === '' || value.includes(':') || value.includes('#') ||
                value.includes("'") || value.includes('"') ||
                value.match(/^[{[\]>|*&!%@`]/) ||
                value === 'true' || value === 'false' ||
                value === 'null' || value === 'yes' || value === 'no') {
                return `"${value.replace(/"/g, '\\"')}"`;
            }
            return value;
        }
        if (typeof value === 'number' || typeof value === 'boolean') {
            return String(value);
        }
        return `"${String(value)}"`;
    }
}
