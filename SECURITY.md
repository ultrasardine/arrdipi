# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in arrdipi, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email:** Send a detailed report to the project maintainers via GitHub's private vulnerability reporting feature at [https://github.com/arrdipi/arrdipi/security/advisories/new](https://github.com/arrdipi/arrdipi/security/advisories/new)
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours of your report
- **Assessment:** Within 7 days, we will assess the severity and confirm the vulnerability
- **Fix timeline:** Critical vulnerabilities will be patched within 14 days; others within 30 days
- **Disclosure:** We will coordinate disclosure with you and credit you in the advisory (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Authentication bypass or credential leakage in NLA/CredSSP handling
- TLS certificate validation bypass
- Memory safety issues in PDU parsing (buffer overflows, out-of-bounds reads)
- Injection vulnerabilities in channel data handling
- Cryptographic weaknesses in Standard RDP Security implementation
- Sensitive data exposure (passwords, session keys) in logs or error messages

### Out of Scope

- Vulnerabilities in upstream dependencies (`cryptography`, `pyspnego`, `av`, `pygame`, `sounddevice`) — report these to the respective projects
- Denial of service via malformed PDUs from a malicious server (arrdipi is a client library; the server is assumed to be partially trusted)
- Issues requiring physical access to the machine running arrdipi

## Security Best Practices for Users

- Always use NLA (`security="nla"`) when connecting to production servers
- Keep `verify_cert=True` (the default) to validate server TLS certificates
- Use environment variables (`ARRDIPI_PASSWORD`) instead of passing passwords on the command line
- Keep arrdipi and its dependencies updated to the latest versions
- Do not expose arrdipi sessions to untrusted networks without additional protection
