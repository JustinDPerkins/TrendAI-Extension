# TrendAI™ Security Scanner

A VS Code extension that integrates Trend Micro's security scanning capabilities directly into your development environment. Scan for vulnerabilities, malware, secrets, and Infrastructure-as-Code (IaC) misconfigurations without leaving your editor.

![VS Code](https://img.shields.io/badge/VS%20Code-1.85+-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

## Features

### Vulnerability Scanning
- Detect known vulnerabilities in application dependencies
- View CVSS scores and NVD references
- Get remediation guidance with fix versions

### Secret Detection
- Identify exposed API keys, credentials, and tokens
- Pinpoint exact line and column locations
- Quick actions to remove or gitignore secrets

### Malware Scanning
- Scan container images for malware
- SHA256-based threat identification

### IaC Template Scanning
- **Terraform** - Single files, projects, and plan JSON
- **CloudFormation** - YAML and JSON templates
- Compliance mapping (PCI-DSS, SOC2, etc.)
- Provider-specific rules for AWS, Azure, GCP

### Docker Build & Scan
- Build and scan Dockerfiles in one step
- Automatic image export and analysis
- Full vulnerability and malware detection

### LLM Application Scanner
- Specialized scanning for AI/LLM applications

## Installation

1. Install from the VS Code Marketplace or Extensions panel
2. Search for "TrendAI Security Scanner"
3. Click Install

Or install from VSIX:
```bash
code --install-extension trendmicro-security-scanner-0.1.0.vsix
```

## Quick Start

1. **Set your API Token**
   - Run command: `TrendAI™: Set API Token`
   - Enter your Vision One API token

2. **Scan a file or directory**
   - Right-click in Explorer → `TrendAI™: Scan File`
   - Or use Command Palette: `TrendAI™: Scan Directory`

3. **View results**
   - Click the shield icon in the Activity Bar
   - Or run: `TrendAI™: Show Results Dashboard`

## Commands

| Command | Description |
|---------|-------------|
| `Scan Directory` | Scan entire directory for vulnerabilities, secrets, and more |
| `Scan File` | Scan a single file |
| `Scan Container Image` | Scan container images from registry or Docker |
| `Scan IaC Template` | Scan Terraform or CloudFormation files |
| `Scan Terraform Project` | Scan entire Terraform project |
| `Build & Scan Dockerfile` | Build Docker image and scan for issues |
| `Scan LLM Application` | Launch scanner for LLM applications |
| `Set API Token` | Configure your Vision One API token |
| `Show Results Dashboard` | Display interactive results panel |
| `Clear Results` | Clear all scan results |

## Supported Artifact Types

**Files & Directories**
- Any file or folder in your workspace

**Container Images**
- Registry images (`nginx:latest`, `myregistry/image:tag`)
- Local Docker daemon images
- Docker archives (`docker save` outputs)
- OCI archives
- Podman images
- Singularity images

**IaC Templates**
- Terraform HCL (`.tf`)
- Terraform Plan JSON
- CloudFormation YAML (`.yaml`, `.yml`)
- CloudFormation JSON (`.json`)

## Configuration

Access settings via `File > Preferences > Settings` and search for "trendmicro".

| Setting | Default | Description |
|---------|---------|-------------|
| `visionOneRegion` | `api.xdr.trendmicro.com` | Vision One API endpoint |
| `tmasPath` | (auto) | Custom path to TMAS binary |
| `tmasRegion` | `us-east-1` | TMAS cloud features region |
| `scanOnSave` | `false` | Auto-scan files on save |
| `severityThreshold` | `medium` | Minimum severity to report |
| `enableVulnerabilities` | `true` | Enable vulnerability scanning |
| `enableMalware` | `true` | Enable malware scanning (containers only) |
| `enableSecrets` | `true` | Enable secrets scanning |

### Vision One Regions

| Region | Endpoint |
|--------|----------|
| United States | `api.xdr.trendmicro.com` |
| Australia | `api.au.xdr.trendmicro.com` |
| Europe | `api.eu.xdr.trendmicro.com` |
| India | `api.in.xdr.trendmicro.com` |
| Japan | `api.xdr.trendmicro.co.jp` |
| Singapore | `api.sg.xdr.trendmicro.com` |

## User Interface

### Activity Bar
The shield icon provides quick access to the TrendAI™ Security panel.

### Results Tree View
Findings organized by category:
```
├── Vulnerabilities (12)
│   ├── CVE-2024-1234 (lodash@4.17.15)
│   └── CVE-2024-5678 (axios@0.21.0)
├── Secrets (3)
│   ├── AWS_API_KEY (config.js:42)
│   └── PRIVATE_KEY (.env:7)
├── Malware (0)
└── IaC Misconfigurations (5)
    ├── S3 Bucket Public Access
    └── Missing Encryption
```

### Results Dashboard
Interactive HTML panel with:
- Severity distribution chart
- Filterable findings by severity
- Expandable details for each issue
- Direct links to affected files
- Remediation guidance

### Status Bar
Shows total issue count with quick access to scanning.

### Code Actions
Right-click on highlighted issues for quick fixes:
- View vulnerability details (NVD links)
- Show available fix versions
- Remove secret lines
- Add files to .gitignore
- Suppress IaC findings with inline comments

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

To use a custom binary, set `trendmicro.tmasPath` in settings.

## How It Works

1. **File/Directory Scanning**: Uses the TMAS binary to analyze files locally, then reports findings inline
2. **Template Scanning**: Uploads IaC files to Vision One API for cloud-based analysis
3. **Container Scanning**: Pulls or exports images, then scans with TMAS
4. **Results**: All findings appear in the tree view, diagnostics panel, and dashboard

## Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| Critical | Red | Immediate action required |
| High | Orange | Should be addressed soon |
| Medium | Yellow | Plan to remediate |
| Low | Blue | Consider fixing |
| Negligible | Gray | Informational |

## Suppressing Findings

For IaC findings, add inline comments to suppress:

**Terraform:**
```hcl
resource "aws_s3_bucket" "example" {
  # tfsec:ignore:aws-s3-enable-versioning
  bucket = "my-bucket"
}
```

**CloudFormation:**
```yaml
Resources:
  MyBucket:
    # cfsec:ignore:aws-s3-enable-versioning
    Type: AWS::S3::Bucket
```

## Troubleshooting

### TMAS binary not found
- Check `trendmicro.tmasPath` setting
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

## Privacy & Security

- API tokens are stored in VS Code's secure storage
- Tokens are never logged or displayed
- Template scans upload files to Trend Micro's cloud for analysis
- Local scans process data on your machine

## License

See [LICENSE](LICENSE) for details.

## Support

- [Report Issues](https://github.com/trendmicro/vscode-security-scanner/issues)
- [Documentation](https://docs.trendmicro.com)

---

Made with security in mind by Trend Micro
