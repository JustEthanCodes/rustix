# Security Policy

## About Rustix Security

Security is an important part of Rustix's development. As an operating system project, Rustix aims to provide a reliable and secure foundation for running software.

Although Rustix is currently under active development and should not be considered production-ready, security vulnerabilities are taken seriously.

## Supported Versions

Rustix is currently in active development.

| Version | Security Support |
|---|---|
| Development (`main`) | Supported |
| Latest release | Supported, where applicable |
| Older releases | Not guaranteed |

Security fixes will generally be prioritised for the latest development version.

## Reporting a Vulnerability

**Please do not publicly disclose security vulnerabilities through GitHub Issues or public discussions.**

If you discover a potential security vulnerability, please report it privately through GitHub Security Advisories:

1. Navigate to the Rustix GitHub repository.
2. Open the **Security** tab.
3. Select **Advisories**.
4. Submit a private vulnerability report.

If private vulnerability reporting is unavailable, contact the project maintainer through a private communication channel, such as emailing security@eura.dev.

Please include as much of the following information as possible:

- A description of the vulnerability.
- The affected component or subsystem.
- Steps to reproduce the issue.
- The potential security impact.
- Any relevant logs, screenshots or proof-of-concept material.

## Response Process

Reports will be reviewed as soon as reasonably possible.

The intended response process is:

1. **Acknowledgement:** Confirm receipt of the report, ideally within 7 days.
2. **Investigation:** Assess the vulnerability, its impact and affected components.
3. **Resolution:** Develop and test an appropriate fix.
4. **Disclosure:** Publish relevant security information once a fix or mitigation is available.

Response times may vary depending on the complexity and severity of the vulnerability.

## Scope

Security reports concerning the following components are particularly relevant:

- Kernel and memory management.
- Bootloader and boot process.
- System calls and privilege boundaries.
- Filesystem implementation and file handling.
- Process and task management.
- Device and hardware interfaces.
- System utilities and bundled components.

Vulnerabilities in third-party dependencies may also be reported.

## Responsible Disclosure

Please allow the maintainer reasonable time to investigate and address a reported vulnerability before publicly disclosing it.

Security researchers are asked to:

- Avoid accessing or modifying data that does not belong to them.
- Avoid disrupting systems or services.
- Avoid testing vulnerabilities against systems without permission.
- Share vulnerability details privately with the maintainer.

The goal is to work collaboratively towards a fix before public disclosure.

## Security Disclaimer

Rustix is an experimental operating system under active development.

It has not undergone a comprehensive independent security audit and should not be relied upon for sensitive or production workloads.

Users should understand the experimental nature of the project before deploying it.