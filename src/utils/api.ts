import * as https from 'https';
import * as http from 'http';

export interface ApiResponse<T = unknown> {
    status: number;
    data: T;
    headers: http.IncomingHttpHeaders;
}

export interface ApiError extends Error {
    status?: number;
    response?: unknown;
}

export interface RequestOptions {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    headers?: Record<string, string>;
    body?: unknown;
    timeout?: number;
}

export class VisionOneApiClient {
    private baseUrl: string;
    private apiToken: string;

    constructor(region: string, apiToken: string) {
        this.baseUrl = `https://${region}`;
        this.apiToken = apiToken;
    }

    updateToken(token: string): void {
        this.apiToken = token;
    }

    updateRegion(region: string): void {
        this.baseUrl = `https://${region}`;
    }

    async request<T>(path: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
        const url = new URL(path, this.baseUrl);
        const { method = 'GET', headers = {}, body, timeout = 60000 } = options;

        const requestHeaders: Record<string, string> = {
            'Authorization': `Bearer ${this.apiToken}`,
            'Content-Type': 'application/json;charset=utf-8',
            'Accept': 'application/json',
            ...headers
        };

        const requestBody = body ? JSON.stringify(body) : undefined;

        return new Promise((resolve, reject) => {
            const req = https.request(url, {
                method,
                headers: requestHeaders,
                timeout
            }, (res) => {
                const chunks: Buffer[] = [];

                res.on('data', (chunk: Buffer) => chunks.push(chunk));
                res.on('end', () => {
                    const responseBody = Buffer.concat(chunks).toString('utf-8');
                    let data: T;

                    try {
                        data = responseBody ? JSON.parse(responseBody) : {} as T;
                    } catch {
                        data = responseBody as unknown as T;
                    }

                    if (res.statusCode && res.statusCode >= 400) {
                        // Extract error message from response if available
                        let errorDetail = '';
                        if (data && typeof data === 'object') {
                            const d = data as Record<string, unknown>;
                            if (d.message) errorDetail = String(d.message);
                            else if (d.error) errorDetail = typeof d.error === 'string' ? d.error : JSON.stringify(d.error);
                            else if (d.detail) errorDetail = String(d.detail);
                            else errorDetail = JSON.stringify(data).substring(0, 200);
                        }
                        const error: ApiError = new Error(
                            `API request failed with status ${res.statusCode}${errorDetail ? `: ${errorDetail}` : ''}`
                        );
                        error.status = res.statusCode;
                        error.response = data;
                        reject(error);
                        return;
                    }

                    resolve({
                        status: res.statusCode || 200,
                        data,
                        headers: res.headers
                    });
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (requestBody) {
                req.write(requestBody);
            }

            req.end();
        });
    }

    async get<T>(path: string, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<ApiResponse<T>> {
        return this.request<T>(path, { ...options, method: 'GET' });
    }

    async post<T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<ApiResponse<T>> {
        return this.request<T>(path, { ...options, method: 'POST', body });
    }

    async postBinary<T>(path: string, data: Buffer, contentType: string, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<ApiResponse<T>> {
        const url = new URL(path, this.baseUrl);
        const timeout = options?.timeout ?? 120000;

        const requestHeaders: Record<string, string> = {
            'Authorization': `Bearer ${this.apiToken}`,
            'Content-Type': contentType,
            'Accept': 'application/json',
            'Content-Length': data.length.toString(),
            ...options?.headers
        };

        return new Promise((resolve, reject) => {
            const req = https.request(url, {
                method: 'POST',
                headers: requestHeaders,
                timeout
            }, (res) => {
                const chunks: Buffer[] = [];

                res.on('data', (chunk: Buffer) => chunks.push(chunk));
                res.on('end', () => {
                    const responseBody = Buffer.concat(chunks).toString('utf-8');
                    let responseData: T;

                    try {
                        responseData = responseBody ? JSON.parse(responseBody) : {} as T;
                    } catch {
                        responseData = responseBody as unknown as T;
                    }

                    if (res.statusCode && res.statusCode >= 400) {
                        let errorDetail = '';
                        if (responseData && typeof responseData === 'object') {
                            const d = responseData as Record<string, unknown>;
                            if (d.message) errorDetail = String(d.message);
                            else if (d.error) errorDetail = typeof d.error === 'string' ? d.error : JSON.stringify(d.error);
                            else if (d.detail) errorDetail = String(d.detail);
                            else errorDetail = JSON.stringify(responseData).substring(0, 200);
                        }
                        const error: ApiError = new Error(
                            `API request failed with status ${res.statusCode}${errorDetail ? `: ${errorDetail}` : ''}`
                        );
                        error.status = res.statusCode;
                        error.response = responseData;
                        reject(error);
                        return;
                    }

                    resolve({
                        status: res.statusCode || 200,
                        data: responseData,
                        headers: res.headers
                    });
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            req.write(data);
            req.end();
        });
    }

    async postMultipart<T>(path: string, fileData: Buffer, fileName: string, formFields?: Record<string, string>, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<ApiResponse<T>> {
        const url = new URL(path, this.baseUrl);
        const timeout = options?.timeout ?? 120000;
        const boundary = '----TrendAIFormBoundary' + Math.random().toString(36).substring(2);

        // Build multipart form body
        const formParts: Buffer[] = [];

        // Add any additional form fields first
        if (formFields) {
            for (const [key, value] of Object.entries(formFields)) {
                formParts.push(Buffer.from(
                    `--${boundary}\r\n` +
                    `Content-Disposition: form-data; name="${key}"\r\n\r\n` +
                    `${value}\r\n`
                ));
            }
        }

        // Add file field
        formParts.push(Buffer.from(
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n` +
            `Content-Type: application/zip\r\n\r\n`
        ));
        formParts.push(fileData);
        formParts.push(Buffer.from('\r\n'));

        // End boundary
        formParts.push(Buffer.from(`--${boundary}--\r\n`));

        const body = Buffer.concat(formParts);

        const requestHeaders: Record<string, string> = {
            'Authorization': `Bearer ${this.apiToken}`,
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            'Accept': 'application/json',
            'Content-Length': body.length.toString(),
            ...options?.headers
        };

        return new Promise((resolve, reject) => {
            const req = https.request(url, {
                method: 'POST',
                headers: requestHeaders,
                timeout
            }, (res) => {
                const chunks: Buffer[] = [];

                res.on('data', (chunk: Buffer) => chunks.push(chunk));
                res.on('end', () => {
                    const responseBody = Buffer.concat(chunks).toString('utf-8');
                    let responseData: T;

                    try {
                        responseData = responseBody ? JSON.parse(responseBody) : {} as T;
                    } catch {
                        responseData = responseBody as unknown as T;
                    }

                    if (res.statusCode && res.statusCode >= 400) {
                        let errorDetail = '';
                        if (responseData && typeof responseData === 'object') {
                            const d = responseData as Record<string, unknown>;
                            if (d.message) errorDetail = String(d.message);
                            else if (d.error) errorDetail = typeof d.error === 'string' ? d.error : JSON.stringify(d.error);
                            else if (d.detail) errorDetail = String(d.detail);
                            else errorDetail = JSON.stringify(responseData).substring(0, 200);
                        }
                        const error: ApiError = new Error(
                            `API request failed with status ${res.statusCode}${errorDetail ? `: ${errorDetail}` : ''}`
                        );
                        error.status = res.statusCode;
                        error.response = responseData;
                        reject(error);
                        return;
                    }

                    resolve({
                        status: res.statusCode || 200,
                        data: responseData,
                        headers: res.headers
                    });
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            req.write(body);
            req.end();
        });
    }
}
