/**
 * Error codes for TrendAI extension
 */
export enum ErrorCode {
    // Authentication errors
    AUTH_TOKEN_MISSING = 'AUTH_001',
    AUTH_TOKEN_INVALID = 'AUTH_002',
    AUTH_TOKEN_EXPIRED = 'AUTH_003',
    AUTH_FORBIDDEN = 'AUTH_004',

    // Network errors
    NETWORK_TIMEOUT = 'NET_001',
    NETWORK_UNREACHABLE = 'NET_002',
    NETWORK_DNS_FAILED = 'NET_003',

    // API errors
    API_RATE_LIMITED = 'API_001',
    API_SERVER_ERROR = 'API_002',
    API_BAD_REQUEST = 'API_003',
    API_NOT_FOUND = 'API_004',
    API_UNAVAILABLE = 'API_005',

    // Scan errors
    SCAN_TMAS_NOT_FOUND = 'SCAN_001',
    SCAN_TMAS_FAILED = 'SCAN_002',
    SCAN_PARSE_ERROR = 'SCAN_003',
    SCAN_FILE_NOT_FOUND = 'SCAN_004',
    SCAN_UNSUPPORTED_TYPE = 'SCAN_005',
    SCAN_PERMISSION_DENIED = 'SCAN_006',
    SCAN_TF_PLAN_REQUIRED = 'SCAN_007',

    // Docker errors
    DOCKER_NOT_RUNNING = 'DOCKER_001',
    DOCKER_BUILD_FAILED = 'DOCKER_002',
    DOCKER_IMAGE_NOT_FOUND = 'DOCKER_003',

    // General errors
    UNKNOWN = 'ERR_999'
}

export interface ParsedError {
    code: ErrorCode;
    message: string;
    details?: string;
    suggestion?: string;
}

/**
 * Parse an error into a user-friendly format
 */
export function parseError(error: unknown): ParsedError {
    if (error instanceof Error) {
        return parseErrorMessage(error.message, error);
    }

    if (typeof error === 'string') {
        return parseErrorMessage(error);
    }

    if (error && typeof error === 'object') {
        // Check for API error structure
        if ('status' in error && typeof (error as { status: number }).status === 'number') {
            return parseApiError(error as { status: number; response?: unknown });
        }
    }

    return {
        code: ErrorCode.UNKNOWN,
        message: 'An unexpected error occurred',
        details: String(error)
    };
}

/**
 * Parse API status code into a user-friendly error
 */
function parseApiStatusCode(status: number, responseMessage?: string): ParsedError {
    switch (status) {
        case 400:
            return {
                code: ErrorCode.API_BAD_REQUEST,
                message: 'Bad request - API rejected the input',
                details: responseMessage || 'The request was malformed or the file format is not supported',
                suggestion: 'For Terraform, ensure files are valid HCL. For CloudFormation, ensure valid YAML/JSON.'
            };

        case 401:
            return {
                code: ErrorCode.AUTH_TOKEN_INVALID,
                message: 'Invalid or expired API token',
                details: responseMessage,
                suggestion: 'Run "TrendAI: Set API Token" to configure a valid token'
            };

        case 403:
            return {
                code: ErrorCode.AUTH_FORBIDDEN,
                message: 'Access denied',
                details: responseMessage || 'Your API token does not have permission for this operation',
                suggestion: 'Check your Vision One API token permissions'
            };

        case 404:
            return {
                code: ErrorCode.API_NOT_FOUND,
                message: 'Resource not found',
                details: responseMessage,
                suggestion: 'Verify the API endpoint and region settings'
            };

        case 429:
            return {
                code: ErrorCode.API_RATE_LIMITED,
                message: 'Rate limit exceeded',
                details: 'Too many requests. Please wait before trying again.',
                suggestion: 'Wait a few minutes and try again'
            };

        case 500:
        case 502:
        case 503:
        case 504:
            return {
                code: ErrorCode.API_SERVER_ERROR,
                message: 'Server error',
                details: responseMessage || `The Vision One API returned an error (${status})`,
                suggestion: 'This is a temporary issue. Please try again later.'
            };

        default:
            return {
                code: ErrorCode.UNKNOWN,
                message: `API error (${status})`,
                details: responseMessage
            };
    }
}

/**
 * Parse API errors based on status code
 */
function parseApiError(error: { status: number; response?: unknown }): ParsedError {
    const responseMessage = extractResponseMessage(error.response);
    return parseApiStatusCode(error.status, responseMessage);
}

/**
 * Parse error messages and map to known patterns
 */
function parseErrorMessage(message: string, originalError?: Error): ParsedError {
    const lowerMessage = message.toLowerCase();

    // Check for API status code patterns like "API request failed with status 400"
    const statusMatch = message.match(/status\s+(\d{3})/i);
    if (statusMatch) {
        const status = parseInt(statusMatch[1], 10);
        // Extract response details from originalError if available
        let responseMessage: string | undefined;
        if (originalError && typeof originalError === 'object' && 'response' in originalError) {
            responseMessage = extractResponseMessage((originalError as { response: unknown }).response);
        }
        return parseApiStatusCode(status, responseMessage);
    }

    // Token/Auth errors
    if (lowerMessage.includes('api token not configured') || lowerMessage.includes('token not configured')) {
        return {
            code: ErrorCode.AUTH_TOKEN_MISSING,
            message: 'API token not configured',
            suggestion: 'Run "TrendAI: Set API Token" to configure your Vision One API token'
        };
    }

    // Network errors
    if (lowerMessage.includes('timeout') || lowerMessage.includes('timed out')) {
        return {
            code: ErrorCode.NETWORK_TIMEOUT,
            message: 'Request timed out',
            details: 'The server took too long to respond',
            suggestion: 'Check your network connection and try again'
        };
    }

    if (lowerMessage.includes('econnrefused') || lowerMessage.includes('connection refused')) {
        return {
            code: ErrorCode.NETWORK_UNREACHABLE,
            message: 'Connection refused',
            details: 'Could not connect to the server',
            suggestion: 'Check if the server is running and accessible'
        };
    }

    if (lowerMessage.includes('enotfound') || lowerMessage.includes('dns')) {
        return {
            code: ErrorCode.NETWORK_DNS_FAILED,
            message: 'DNS lookup failed',
            details: 'Could not resolve the server hostname',
            suggestion: 'Check your network connection and DNS settings'
        };
    }

    // TMAS errors
    if (lowerMessage.includes('tmas binary not found') || lowerMessage.includes('tmas not found')) {
        return {
            code: ErrorCode.SCAN_TMAS_NOT_FOUND,
            message: 'TMAS binary not found',
            details: 'The TMAS scanning tool could not be found',
            suggestion: 'The extension will attempt to download TMAS automatically. Check network access.'
        };
    }

    if (lowerMessage.includes('tmas scan failed') || lowerMessage.includes('exit code')) {
        return {
            code: ErrorCode.SCAN_TMAS_FAILED,
            message: 'Scan failed',
            details: message,
            suggestion: 'Check the Output panel for detailed error information'
        };
    }

    if (lowerMessage.includes('failed to parse')) {
        return {
            code: ErrorCode.SCAN_PARSE_ERROR,
            message: 'Failed to parse scan results',
            details: message,
            suggestion: 'This may be a temporary issue. Try running the scan again.'
        };
    }

    // File errors
    if (lowerMessage.includes('enoent') || lowerMessage.includes('no such file')) {
        return {
            code: ErrorCode.SCAN_FILE_NOT_FOUND,
            message: 'File not found',
            details: message,
            suggestion: 'Verify the file exists and the path is correct'
        };
    }

    if (lowerMessage.includes('unsupported') || lowerMessage.includes('not supported')) {
        return {
            code: ErrorCode.SCAN_UNSUPPORTED_TYPE,
            message: 'Unsupported file type',
            details: message,
            suggestion: 'Only Terraform plan JSON and CloudFormation (.yaml, .yml, .json) files are supported for IaC scanning'
        };
    }

    // Terraform plan required
    if (lowerMessage.includes('terraform plan json') || lowerMessage.includes('not raw hcl')) {
        return {
            code: ErrorCode.SCAN_TF_PLAN_REQUIRED,
            message: 'Terraform plan JSON required',
            details: 'Vision One API cannot scan raw Terraform HCL files directly',
            suggestion: 'Run: terraform plan -out=tfplan && terraform show -json tfplan > plan.json'
        };
    }

    if (lowerMessage.includes('permission denied') || lowerMessage.includes('eacces')) {
        return {
            code: ErrorCode.SCAN_PERMISSION_DENIED,
            message: 'Permission denied',
            details: message,
            suggestion: 'Check file permissions and try again'
        };
    }

    // Docker errors
    if (lowerMessage.includes('docker daemon') || lowerMessage.includes('docker is not running')) {
        return {
            code: ErrorCode.DOCKER_NOT_RUNNING,
            message: 'Docker is not running',
            details: 'The Docker daemon is not accessible',
            suggestion: 'Start Docker Desktop or the Docker daemon and try again'
        };
    }

    if (lowerMessage.includes('docker build failed') || lowerMessage.includes('docker command failed')) {
        return {
            code: ErrorCode.DOCKER_BUILD_FAILED,
            message: 'Docker build failed',
            details: message,
            suggestion: 'Check the Dockerfile for errors and try again'
        };
    }

    // Default
    return {
        code: ErrorCode.UNKNOWN,
        message: message.length > 100 ? message.substring(0, 100) + '...' : message,
        details: originalError?.stack
    };
}

/**
 * Extract a message from an API response body
 */
function extractResponseMessage(response: unknown): string | undefined {
    if (!response || typeof response !== 'object') {
        return undefined;
    }

    const resp = response as Record<string, unknown>;

    // Try common error message fields
    if (typeof resp.message === 'string') {
        return resp.message;
    }
    if (typeof resp.error === 'string') {
        return resp.error;
    }
    if (resp.error && typeof resp.error === 'object' && typeof (resp.error as Record<string, unknown>).message === 'string') {
        return (resp.error as Record<string, unknown>).message as string;
    }
    if (typeof resp.detail === 'string') {
        return resp.detail;
    }

    return undefined;
}

/**
 * Create a ScanError object from a parsed error
 */
export function toScanError(parsed: ParsedError, file?: string): {
    code: string;
    message: string;
    details?: string;
    file?: string;
    timestamp: string;
} {
    return {
        code: parsed.code,
        message: parsed.suggestion ? `${parsed.message}. ${parsed.suggestion}` : parsed.message,
        details: parsed.details,
        file,
        timestamp: new Date().toISOString()
    };
}
