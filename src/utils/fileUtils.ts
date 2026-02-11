import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import archiver from 'archiver';

export function fileExists(filePath: string): boolean {
    try {
        return fs.existsSync(filePath);
    } catch {
        return false;
    }
}

export function isDirectory(filePath: string): boolean {
    try {
        return fs.statSync(filePath).isDirectory();
    } catch {
        return false;
    }
}

export function readFileContent(filePath: string): string {
    return fs.readFileSync(filePath, 'utf-8');
}

export function writeFileContent(filePath: string, content: string): void {
    fs.writeFileSync(filePath, content, 'utf-8');
}

export function ensureDirectory(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
}

export function getFileExtension(filePath: string): string {
    return path.extname(filePath).toLowerCase();
}

export function isTerraformFile(filePath: string): boolean {
    return getFileExtension(filePath) === '.tf';
}

export function isCloudFormationFile(filePath: string): boolean {
    const ext = getFileExtension(filePath);
    if (ext !== '.yaml' && ext !== '.yml' && ext !== '.json') {
        return false;
    }

    try {
        const content = readFileContent(filePath);
        // Check for CloudFormation markers
        return content.includes('AWSTemplateFormatVersion') ||
               content.includes('Resources:') ||
               content.includes('"Resources"');
    } catch {
        return false;
    }
}

export function isIaCFile(filePath: string): boolean {
    return isTerraformFile(filePath) || isCloudFormationFile(filePath);
}

export async function createTerraformArchive(dirPath: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        const archive = archiver('zip', { zlib: { level: 9 } });

        archive.on('data', (chunk: Buffer) => chunks.push(chunk));
        archive.on('end', () => resolve(Buffer.concat(chunks)));
        archive.on('error', reject);

        // Add all .tf files from the directory
        archive.glob('**/*.tf', { cwd: dirPath });
        // Also include .tfvars files
        archive.glob('**/*.tfvars', { cwd: dirPath });

        archive.finalize();
    });
}

export function findTerraformFiles(dirPath: string): string[] {
    const files: string[] = [];

    function walk(dir: string): void {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                // Skip common non-essential directories
                if (!entry.name.startsWith('.') && entry.name !== 'node_modules') {
                    walk(fullPath);
                }
            } else if (entry.name.endsWith('.tf')) {
                files.push(fullPath);
            }
        }
    }

    walk(dirPath);
    return files;
}

export function findIaCFiles(dirPath: string): { terraform: string[]; cloudformation: string[] } {
    const terraform: string[] = [];
    const cloudformation: string[] = [];

    function walk(dir: string): void {
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    // Skip common non-essential directories
                    if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== 'build') {
                        walk(fullPath);
                    }
                } else if (entry.name.endsWith('.tf')) {
                    terraform.push(fullPath);
                } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml') || entry.name.endsWith('.json')) {
                    // Check if it's a CloudFormation file
                    if (isCloudFormationFile(fullPath)) {
                        cloudformation.push(fullPath);
                    }
                }
            }
        } catch {
            // Ignore permission errors
        }
    }

    walk(dirPath);
    return { terraform, cloudformation };
}

export function getPlatformInfo(): { platform: NodeJS.Platform; arch: string } {
    const platform = os.platform();
    let arch = os.arch();

    // Normalize architecture names to match TMAS download URLs
    if (arch === 'x64') {
        arch = 'x86_64';
    }
    // arm64 stays as arm64

    return { platform, arch };
}

export function getTempDirectory(): string {
    return os.tmpdir();
}

export function makeExecutable(filePath: string): void {
    if (os.platform() !== 'win32') {
        fs.chmodSync(filePath, 0o755);
    }
}

export async function downloadFile(url: string, destPath: string): Promise<void> {
    const https = await import('https');
    const http = await import('http');
    const fsModule = await import('fs');
    const urlModule = await import('url');

    return new Promise((resolve, reject) => {
        const file = fsModule.createWriteStream(destPath);
        const parsedUrl = new urlModule.URL(url);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;

        const options = {
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname + parsedUrl.search,
            headers: {
                'User-Agent': 'TrendAI-VSCode-Extension/1.0',
                'Accept': '*/*'
            }
        };

        const request = protocol.get(options, (response) => {
            // Handle redirects
            if (response.statusCode === 301 || response.statusCode === 302 || response.statusCode === 303 || response.statusCode === 307 || response.statusCode === 308) {
                const redirectUrl = response.headers.location;
                if (redirectUrl) {
                    file.close();
                    if (fsModule.existsSync(destPath)) {
                        fsModule.unlinkSync(destPath);
                    }
                    // Handle relative redirects
                    const fullRedirectUrl = redirectUrl.startsWith('http') ? redirectUrl : `${parsedUrl.protocol}//${parsedUrl.host}${redirectUrl}`;
                    downloadFile(fullRedirectUrl, destPath).then(resolve).catch(reject);
                    return;
                }
            }

            if (response.statusCode !== 200) {
                file.close();
                if (fsModule.existsSync(destPath)) {
                    fsModule.unlinkSync(destPath);
                }
                reject(new Error(`Failed to download: ${response.statusCode}`));
                return;
            }

            response.pipe(file);

            file.on('finish', () => {
                file.close();
                resolve();
            });
        });

        request.on('error', (err) => {
            file.close();
            if (fsModule.existsSync(destPath)) {
                fsModule.unlinkSync(destPath);
            }
            reject(err);
        });

        file.on('error', (err) => {
            file.close();
            if (fsModule.existsSync(destPath)) {
                fsModule.unlinkSync(destPath);
            }
            reject(err);
        });
    });
}
