# TrendAI™ Security Scanner

A VS Code extension that integrates TrendAI's security scanning capabilities directly into your development environment. Scan for vulnerabilities, malware, secrets, and Infrastructure-as-Code (IaC) misconfigurations without leaving your editor.

> **Disclaimer:** This is an unofficial community project and is not officially supported by TrendAI. Use at your own discretion.

![VS Code](https://img.shields.io/badge/VS%20Code-1.85+-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

## Features

### Unified Security Scanning
- **One command scans everything** - IaC misconfigurations, vulnerabilities, and secrets
- Holistic security view in a single results dashboard
- Filter results by type (IaC, Vulnerabilities, Secrets) or severity

### Vulnerability Scanning
- Detect known vulnerabilities in application dependencies
- View CVSS scores and NVD references
- Get remediation guidance with fix versions

### Secret Detection
- Identify exposed API keys, credentials, and tokens
- Pinpoint exact line and column locations
- Quick actions to add files to .gitignore

### IaC Template Scanning
- **Terraform** - Single files, projects, and plan JSON
- **CloudFormation** - YAML and JSON templates
- Compliance mapping (PCI-DSS, SOC2, etc.)
- Provider-specific rules for AWS, Azure, GCP

### Docker Build & Scan
- Build and scan Dockerfiles in one step
- Automatic image export and analysis
- Full vulnerability, malware, and secrets detection

### LLM Security Scanner
- Test AI/LLM endpoints for prompt injection vulnerabilities
- Supports Ollama, LM Studio, OpenAI, Azure OpenAI, and custom endpoints
- Automated model discovery and attack objective testing

## Installation

1. Install from the VS Code Marketplace or Extensions panel
2. Search for "TrendAI Security Scanner"
3. Click Install

Or install from VSIX:
```bash
code --install-extension trendai-security-scanner-0.1.0.vsix
```

## Quick Start

1. **Set your API Token**
   - Run command: `TrendAI™: Set API Token`
   - Enter your Vision One API token

2. **Scan your project**
   - Right-click a folder in Explorer → `TrendAI™: Scan (IaC, Secrets, Vulns)`
   - Or use Command Palette (Ctrl/Cmd+Shift+P) → `TrendAI™: Scan (IaC, Secrets, Vulns)`

3. **View results**
   - Results appear in the interactive dashboard
   - Filter by type: All | IaC | Vulnerabilities | Secrets
   - Filter by severity: Critical | High | Medium | Low

## Commands

| Command | Description |
|---------|-------------|
| `Scan (IaC, Secrets, Vulns)` | Unified scan for IaC misconfigurations, vulnerabilities, and secrets |
| `LLM Scan (AI Security)` | Scan LLM/AI endpoints for prompt injection vulnerabilities |
| `Build & Scan Dockerfile` | Build Docker image and scan for security issues |
| `Set API Token` | Configure your Vision One API token |
| `Show Results Dashboard` | Display interactive results panel |
| `Refresh Results` | Refresh the results tree view |
| `Clear Results` | Clear all scan results |

## Scan Behavior

| Context | Action |
|---------|--------|
| Right-click folder | Scans that folder recursively |
| Right-click file | Scans the file's parent folder |
| Command palette | Scans entire workspace (prompts for selection if multi-root) |

## Supported File Types

**IaC Templates**
- Terraform HCL (`.tf`)
- Terraform Plan JSON
- CloudFormation YAML (`.yaml`, `.yml`)
- CloudFormation JSON (`.json`)

**Dependency Files**
- `package.json`, `package-lock.json`
- `requirements.txt`, `Pipfile`, `poetry.lock`
- `go.mod`, `go.sum`
- `pom.xml`, `build.gradle`
- And many more...

**Docker**
- Dockerfiles for build & scan workflow

## Configuration

Access settings via `File > Preferences > Settings` and search for "trendai".

| Setting | Default | Description |
|---------|---------|-------------|
| `trendai.visionOneRegion` | `api.xdr.trendmicro.com` | Vision One API endpoint |
| `trendai.tmasPath` | (auto) | Custom path to TMAS binary |
| `trendai.tmasRegion` | `us-east-1` | TMAS cloud features region |
| `trendai.scanOnSave` | `false` | Auto-scan IaC files on save |
| `trendai.severityThreshold` | `medium` | Minimum severity to report |
| `trendai.enableVulnerabilities` | `true` | Enable vulnerability scanning |
| `trendai.enableMalware` | `true` | Enable malware scanning (containers only) |
| `trendai.enableSecrets` | `true` | Enable secrets scanning |

### Vision One Regions

| Region | Endpoint |
|--------|----------|
| United States | `api.xdr.trendmicro.com` |
| United States (Government) | `api.usgov.xdr.trendmicro.com` |
| Australia | `api.au.xdr.trendmicro.com` |
| Germany | `api.eu.xdr.trendmicro.com` |
| India | `api.in.xdr.trendmicro.com` |
| Japan | `api.xdr.trendmicro.co.jp` |
| Singapore | `api.sg.xdr.trendmicro.com` |
| United Arab Emirates | `api.mea.xdr.trendmicro.com` |
| United Kingdom | `api.uk.xdr.trendmicro.com` |

## Results Dashboard

The interactive results panel includes:

- **Overview Summary** - Severity breakdown at a glance
- **Type Tabs** - Filter by All | IaC | Vulnerabilities | Secrets
- **Severity Filters** - Focus on Critical, High, Medium, or Low issues
- **File Grouping** - Findings organized by file and resource
- **Expandable Details** - Full descriptions, remediation guidance, and links
- **Scan Summary** - Shows success/failure counts when errors occur
- **Error Display** - Clear error messages with troubleshooting suggestions

## Error Handling

The extension provides detailed error feedback:

| Error Code | Description |
|------------|-------------|
| `AUTH_001` | API token not configured |
| `AUTH_002` | Invalid or expired API token |
| `API_001` | Rate limit exceeded |
| `API_002` | Server error (try again later) |
| `SCAN_001` | TMAS binary not found |
| `NET_001` | Request timeout |

Errors are displayed in:
- The results dashboard (with full context)
- VS Code notifications (with suggestions)
- Output panel (`TrendAI™ Security`) for detailed logs

## Prerequisites

### Required
- VS Code 1.85.0 or later
- Vision One API token ([Get one here](https://www.trendmicro.com/en_us/business/products/detection-response/xdr.html))
- Internet connectivity

### For Docker Scanning
- Docker daemon running
- `docker` CLI in PATH

### TMAS Binary
The extension automatically downloads the TMAS binary for your platform:
- macOS (ARM64, x86_64)
- Linux (ARM64, x86_64)
- Windows (ARM64, x86_64)

To use a custom binary, set `trendai.tmasPath` in settings.

## Troubleshooting

### TMAS binary not found
- Check `trendai.tmasPath` setting
- Ensure network access for auto-download
- Verify platform compatibility

### API token issues
- Run `TrendAI™: Set API Token` to reconfigure
- Verify token has correct permissions
- Check selected region matches your account

### No results appearing
- Check the Output panel (`TrendAI™ Security`) for errors
- Verify file types are supported
- Ensure severity threshold isn't filtering results

### Scan errors
- Check the results dashboard for detailed error information
- Look for error codes in the Output panel
- Verify network connectivity to Vision One API

## Privacy & Security

- API tokens are stored in VS Code's secure storage
- Tokens are never logged or displayed
- IaC template scans upload files to Vision One API for cloud-based analysis
- Vulnerability and secrets scans process data locally with TMAS

## License

See [LICENSE](LICENSE) for details.

## Support

- [Report Issues](https://github.com/JustinDPerkins/TrendAI-Extension/issues)
- [Documentation](https://github.com/JustinDPerkins/TrendAI-Extension)

---

Made with security in mind by [Justin Perkins](https://github.com/JustinDPerkins)
