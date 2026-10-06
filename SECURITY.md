# Security Policy

## Supported Versions

Only the latest release branch of HookArmor receives active security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| < 1.2.0 | :x:                |

## Reporting a Vulnerability

We take the security of HookArmor and the webhook integrity of applications using it seriously.

If you believe you have discovered a security vulnerability in HookArmor:

1. **Do NOT report security vulnerabilities via public GitHub issues or discussions.**
2. Send a detailed report directly via email to: `security@hookarmor.dev` (or open a private GitHub Security Advisory).
3. Please include:
   - Type of issue (e.g. signature verification bypass, SSRF, authentication bypass, data leak)
   - Step-by-step reproduction instructions or proof-of-concept script
   - Affected versions and configurations

### Response SLA
- **Initial Acknowledgement**: Within 24–48 hours.
- **Triage & Reproduction**: Within 72 hours.
- **Fix & Patch Release**: High-severity vulnerabilities will receive an emergency patch release within 5 business days.

## Security Architecture & Best Practices

- **Ingress Signature Verification**: Always configure endpoint signing secrets (`whsec_...`) so incoming webhooks are cryptographically authenticated against spoofing before entry into the queue.
- **Secrets at Rest**: Set `HOOKARMOR_ENCRYPTION_KEY` (32+ random characters) to encrypt all endpoint signing secrets with AES-256-GCM at rest.
- **Outbound SSRF Protection**: In production environments, HookArmor enforces strict SSRF protections by default, validating both destination URLs and resolved IP addresses against private and loopback subnets.
- **API Key Protection**: Never run a public instance without `HOOKARMOR_API_KEY`. Without an API key, management endpoints are restricted strictly to loopback interfaces.
