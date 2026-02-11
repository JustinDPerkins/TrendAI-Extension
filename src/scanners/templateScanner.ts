import * as vscode from 'vscode';
import * as path from 'path';
import { VisionOneApiClient } from '../utils/api';
import { SettingsManager } from '../config/settings';
import { readFileContent, createTerraformArchive, isTerraformFile, isCloudFormationFile, findTerraformFiles } from '../utils/fileUtils';

export interface TemplateScanRule {
    id: string;
    name: string;
    description?: string;
    severity: string;
    category?: string;
    provider?: string;
    service?: string;
}

export interface TemplateScanFinding {
    ruleId: string;
    ruleName?: string;
    severity: string;
    description?: string;
    resource?: string;
    resourceId?: string;
    resourceType?: string;
    file?: string;
    line?: number;
    column?: number;
    recommendation?: string;
    link?: string;
    checkDetails?: CheckDetails;
}

export interface CheckDetails {
    id: string;
    name: string;
    description?: string;
    severity?: string;
    provider?: string;
    service?: string;
    category?: string;
    remediationNotes?: string;
    complianceStandards?: Array<{ id: string; name?: string }>;
    knowledgeBaseUrl?: string;
}

export interface TemplateScanResult {
    findings: TemplateScanFinding[];
    scanId?: string;
    templateType: 'cloudformation' | 'terraform';
    scannedAt: string;
}

export interface CloudFormationScanRequest {
    templateType: 'cloudFormation';
    templateContent: string;
}

export interface TerraformScanRequest {
    templateType: 'terraform';
    templateContent: string;
}

interface ApiScanResponse {
    scanResults?: Array<{
        id?: string;
        ruleId?: string;
        ruleTitle?: string;
        riskLevel?: string;
        status?: string;
        description?: string;
        resource?: string;
        resourceType?: string;
        resourceId?: string;
        resourceLink?: string;
        service?: string;
        provider?: string;
        region?: string;
        resolutionReferenceLink?: string;
        categories?: string[];
        complianceStandards?: Array<{ id: string }>;
    }>;
    missingParameters?: string[];
    skippedRules?: Array<{
        id: string;
        resourceId?: string;
        errorMessage?: string;
    }>;
}

export class TemplateScanner {
    private apiClient: VisionOneApiClient;
    private settingsManager: SettingsManager;
    private outputChannel: vscode.OutputChannel;

    constructor(settingsManager: SettingsManager, outputChannel: vscode.OutputChannel) {
        this.settingsManager = settingsManager;
        this.outputChannel = outputChannel;

        const settings = settingsManager.getSettings();
        this.apiClient = new VisionOneApiClient(settings.visionOneRegion, '');
    }

    async initialize(): Promise<void> {
        const token = await this.settingsManager.getApiToken();
        if (token) {
            this.apiClient.updateToken(token);
        }
    }

    async updateCredentials(): Promise<void> {
        const settings = this.settingsManager.getSettings();
        const token = await this.settingsManager.getApiToken();

        this.apiClient.updateRegion(settings.visionOneRegion);
        if (token) {
            this.apiClient.updateToken(token);
        }
    }

    async getCloudFormationRules(): Promise<TemplateScanRule[]> {
        await this.updateCredentials();

        const response = await this.apiClient.get<{ rules: TemplateScanRule[] }>(
            '/beta/cloudPosture/cloudformationTemplateScannerRules'
        );

        return response.data.rules || [];
    }

    async getTerraformRules(): Promise<TemplateScanRule[]> {
        await this.updateCredentials();

        const response = await this.apiClient.get<{ rules: TemplateScanRule[] }>(
            '/beta/cloudPosture/terraformTemplateScannerRules'
        );

        return response.data.rules || [];
    }

    async scanCloudFormationTemplate(content: string, fileName?: string): Promise<TemplateScanResult> {
        await this.updateCredentials();

        this.outputChannel.appendLine(`Scanning CloudFormation template${fileName ? `: ${fileName}` : ''}...`);

        const response = await this.apiClient.post<ApiScanResponse>(
            '/beta/cloudPosture/scanTemplate',
            {
                type: 'cloudformation-template',
                content: content
            }
        );

        return this.parseApiResponse(response.data, 'cloudformation', fileName);
    }

    async scanTerraformFile(filePath: string): Promise<TemplateScanResult> {
        await this.updateCredentials();

        this.outputChannel.appendLine(`Scanning Terraform file: ${filePath}...`);

        // Terraform HCL (.tf) files must be scanned via the archive endpoint
        // Only Terraform plan JSON can use the template endpoint
        const content = readFileContent(filePath);

        // Check if this is a Terraform plan JSON (not HCL)
        if (this.isTerraformPlanJson(content)) {
            this.outputChannel.appendLine('Detected Terraform plan JSON, using template endpoint');
            const response = await this.apiClient.post<ApiScanResponse>(
                '/beta/cloudPosture/scanTemplate',
                {
                    type: 'terraform-template',
                    content: content
                }
            );
            return this.parseApiResponse(response.data, 'terraform', filePath);
        }

        // For HCL .tf files, create a single-file archive and use archive endpoint
        this.outputChannel.appendLine('Terraform HCL file detected, using archive endpoint');
        const archive = await createTerraformArchive(path.dirname(filePath));
        return await this.scanTerraformArchive(archive, filePath);
    }

    private isTerraformPlanJson(content: string): boolean {
        try {
            const parsed = JSON.parse(content);
            // Terraform plan JSON has specific structure
            return parsed.format_version !== undefined ||
                   parsed.terraform_version !== undefined ||
                   parsed.planned_values !== undefined;
        } catch {
            // Not valid JSON, so it's HCL
            return false;
        }
    }

    async scanTerraformArchive(archiveData: Buffer, fileName?: string): Promise<TemplateScanResult> {
        await this.updateCredentials();

        this.outputChannel.appendLine('Scanning Terraform archive...');

        const response = await this.apiClient.postMultipart<ApiScanResponse>(
            '/beta/cloudPosture/scanTemplateArchive',
            archiveData,
            'terraform-project.zip',
            { type: 'terraform-archive' }
        );

        return this.parseApiResponse(response.data, 'terraform', fileName);
    }

    async scanTerraformProject(dirPath: string): Promise<TemplateScanResult> {
        const tfFiles = findTerraformFiles(dirPath);

        if (tfFiles.length === 0) {
            throw new Error('No Terraform files found in directory');
        }

        this.outputChannel.appendLine(`Found ${tfFiles.length} Terraform files in ${dirPath}`);

        // Try to generate and use Terraform plan JSON (more reliable)
        const settings = this.settingsManager.getSettings();
        if (settings.useTerraformPlan) {
            try {
                const planJson = await this.generateTerraformPlanJson(dirPath);
                if (planJson) {
                    this.outputChannel.appendLine('Using Terraform plan JSON for scanning');
                    return await this.scanTerraformPlanJson(planJson, dirPath);
                }
            } catch (err) {
                this.outputChannel.appendLine(`Terraform plan generation failed: ${err}`);
                this.outputChannel.appendLine('Falling back to HCL archive scanning...');
            }
        } else {
            this.outputChannel.appendLine('Terraform plan generation disabled, using HCL archive');
        }

        // Fallback: Create archive and scan raw HCL
        const archive = await createTerraformArchive(dirPath);
        return await this.scanTerraformArchive(archive, dirPath);
    }

    /**
     * Generate Terraform plan JSON from a directory
     * Returns the plan JSON content, or null if terraform is not available
     */
    private async generateTerraformPlanJson(dirPath: string): Promise<string | null> {
        const { exec } = require('child_process');
        const fs = require('fs');
        const path = require('path');
        const os = require('os');

        // Check if terraform is available
        const terraformAvailable = await new Promise<boolean>((resolve) => {
            exec('terraform version', { timeout: 5000 }, (error: Error | null) => {
                resolve(!error);
            });
        });

        if (!terraformAvailable) {
            this.outputChannel.appendLine('Terraform CLI not found, skipping plan generation');
            return null;
        }

        const tempPlanFile = path.join(os.tmpdir(), `trendai-tfplan-${Date.now()}`);

        try {
            // Check if already initialized
            const tfDirExists = fs.existsSync(path.join(dirPath, '.terraform'));

            if (!tfDirExists) {
                this.outputChannel.appendLine('Running terraform init...');
                await this.runTerraformCommand('terraform init -backend=false -input=false', dirPath);
            }

            // Generate plan
            this.outputChannel.appendLine('Running terraform plan...');
            await this.runTerraformCommand(`terraform plan -out="${tempPlanFile}" -input=false`, dirPath);

            // Convert to JSON - capture stdout directly instead of shell redirection
            this.outputChannel.appendLine('Converting plan to JSON...');
            const planJson = await this.runTerraformCommand(`terraform show -json "${tempPlanFile}"`, dirPath);

            if (!planJson || planJson.trim().length === 0) {
                throw new Error('Terraform show returned empty output');
            }

            this.outputChannel.appendLine(`Plan JSON size: ${planJson.length} bytes`);

            // Cleanup
            if (fs.existsSync(tempPlanFile)) fs.unlinkSync(tempPlanFile);

            return planJson;
        } catch (err) {
            // Cleanup on error
            if (fs.existsSync(tempPlanFile)) fs.unlinkSync(tempPlanFile);
            throw err;
        }
    }

    /**
     * Run a terraform command in a directory
     */
    private runTerraformCommand(command: string, cwd: string): Promise<string> {
        const { exec } = require('child_process');

        return new Promise((resolve, reject) => {
            exec(command, {
                cwd,
                timeout: 120000,
                maxBuffer: 50 * 1024 * 1024,
                shell: true
            }, (error: Error | null, stdout: string, stderr: string) => {
                if (error) {
                    this.outputChannel.appendLine(`Command failed: ${command}`);
                    this.outputChannel.appendLine(`stderr: ${stderr}`);
                    reject(new Error(`Terraform command failed: ${stderr || error.message}`));
                    return;
                }
                resolve(stdout);
            });
        });
    }

    /**
     * Scan Terraform plan JSON content
     */
    private async scanTerraformPlanJson(planJson: string, dirPath?: string): Promise<TemplateScanResult> {
        await this.updateCredentials();

        this.outputChannel.appendLine('Scanning Terraform plan JSON...');

        const response = await this.apiClient.post<ApiScanResponse>(
            '/beta/cloudPosture/scanTemplate',
            {
                type: 'terraform-template',
                content: planJson
            }
        );

        return this.parseApiResponse(response.data, 'terraform', dirPath);
    }

    async scanFile(filePath: string): Promise<TemplateScanResult> {
        if (isTerraformFile(filePath)) {
            return await this.scanTerraformFile(filePath);
        } else if (isCloudFormationFile(filePath)) {
            const content = readFileContent(filePath);
            return await this.scanCloudFormationTemplate(content, filePath);
        } else {
            throw new Error('Unsupported template type. Only Terraform (.tf) and CloudFormation (.yaml, .yml, .json) files are supported.');
        }
    }

    private parseApiResponse(response: ApiScanResponse, templateType: 'cloudformation' | 'terraform', fileName?: string): TemplateScanResult {
        const rawFindings = response.scanResults || [];

        const findings: TemplateScanFinding[] = rawFindings
            .filter(f => f.status !== 'SUCCESS') // Only include failures
            .map(f => ({
                ruleId: f.ruleId || f.id || 'unknown',
                ruleName: f.ruleTitle,
                severity: this.mapRiskLevel(f.riskLevel),
                description: f.description,
                resource: f.resourceId || f.resource,
                resourceId: f.resourceId,
                resourceType: f.resourceType,
                file: fileName,
                recommendation: f.resolutionReferenceLink
                    ? `See: ${f.resolutionReferenceLink.replace(/"/g, '')}`
                    : undefined,
                link: f.resolutionReferenceLink?.replace(/"/g, '')
            }));

        return {
            findings,
            templateType,
            scannedAt: new Date().toISOString()
        };
    }

    private mapRiskLevel(riskLevel?: string): string {
        if (!riskLevel) return 'medium';
        const level = riskLevel.toLowerCase();
        if (level === 'very_high' || level === 'very high') return 'critical';
        return level;
    }

    async testConnection(): Promise<boolean> {
        try {
            await this.getCloudFormationRules();
            return true;
        } catch (error) {
            this.outputChannel.appendLine(`Connection test failed: ${error}`);
            return false;
        }
    }

    async getCheckDetails(checkId: string): Promise<CheckDetails | null> {
        await this.updateCredentials();

        try {
            const response = await this.apiClient.get<CheckDetailsResponse>(
                `/beta/cloudPosture/checks/${checkId}`
            );

            const data = response.data;
            return {
                id: data.ruleId || data.id || checkId,
                name: data.ruleTitle || checkId,
                description: data.description,
                severity: data.riskLevel,
                provider: data.provider,
                service: data.service,
                category: data.categories?.join(', '),
                remediationNotes: data.note,
                complianceStandards: data.complianceStandards,
                knowledgeBaseUrl: data.resolutionReferenceLink
            };
        } catch (error) {
            this.outputChannel.appendLine(`Failed to fetch check details for ${checkId}: ${error}`);
            return null;
        }
    }

    async enrichFindingsWithCheckDetails(result: TemplateScanResult): Promise<TemplateScanResult> {
        this.outputChannel.appendLine('Fetching check details for findings...');

        // Get unique rule IDs
        const ruleIds = [...new Set(result.findings.map(f => f.ruleId))];

        // Fetch check details for each unique rule ID (in parallel, max 5 at a time)
        const checkDetailsMap = new Map<string, CheckDetails>();

        for (let i = 0; i < ruleIds.length; i += 5) {
            const batch = ruleIds.slice(i, i + 5);
            const details = await Promise.all(
                batch.map(id => this.getCheckDetails(id))
            );

            batch.forEach((id, index) => {
                if (details[index]) {
                    checkDetailsMap.set(id, details[index]!);
                }
            });
        }

        // Enrich findings with check details
        const enrichedFindings = result.findings.map(finding => {
            const details = checkDetailsMap.get(finding.ruleId);
            if (details) {
                return {
                    ...finding,
                    checkDetails: details,
                    ruleName: details.name || finding.ruleName,
                    description: details.description || finding.description,
                    recommendation: details.remediationNotes || finding.recommendation,
                    link: details.knowledgeBaseUrl || finding.link
                };
            }
            return finding;
        });

        this.outputChannel.appendLine(`Enriched ${checkDetailsMap.size} findings with check details`);

        return {
            ...result,
            findings: enrichedFindings
        };
    }
}

interface CheckDetailsResponse {
    id?: string;
    ruleId?: string;
    ruleTitle?: string;
    description?: string;
    riskLevel?: string;
    provider?: string;
    service?: string;
    categories?: string[];
    resource?: string;
    resourceName?: string;
    resourceType?: string;
    region?: string;
    status?: string;
    complianceStandards?: Array<{ id: string; name?: string }>;
    resolutionReferenceLink?: string;
    resourceLink?: string;
    note?: string;
    extraData?: Array<{ label: string; name: string; type: string; value: string }>;
}
