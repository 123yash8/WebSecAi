# WebSecAi


## Overview

This project is a powerful, intelligent, and modular web application vulnerability scanner designed to identify security flaws commonly found in modern web applications. It combines traditional scanning techniques with AI-based validation to reduce false positives, provide contextual understanding, and assist in post-scan remediation.

The scanner is specifically built around the OWASP Top 10 vulnerabilities and includes separate scanning modules for each vulnerability category. After a scan is completed, an AI model[LLM] is used to validate the results by analyzing code patterns, behavior, and application responses. The goal is to emulate a human-like reasoning process while maintaining the speed and breadth of automated tools.

---

## Key Features

### Modular Architecture

The scanner is structured in a way that each vulnerability is tested by a dedicated module. This design promotes better maintainability and enables users to easily add, remove, or upgrade individual components. Each module operates independently and can be plugged or removed from the main scanner engine.

### AI-Powered Validation Layer

After the raw vulnerability scan is conducted, all findings are passed to a secondary validation layer powered by an AI model. This model can analyze various data inputs such as source code snippets (if available), HTTP responses, server behaviors, and logs to validate whether a finding is likely to be exploitable. This helps eliminate common false positives associated with heuristic scanning techniques.

The AI model also provides a brief human-readable explanation and ranks the finding by severity, confidence, and impact.

### Support for OWASP Top 10

The scanner currently includes detection capabilities for:

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Security Misconfigurations
- Insecure Deserialization
- Broken Authentication
- Broken Access Control
- Server-Side Request Forgery (SSRF)
- Sensitive Data Exposure
- Vulnerable Components Usage

Each of these categories is handled by a standalone scanner script and supports user customization.

### AI-Assisted Reporting

After a scan is completed, a detailed report is generated in human-readable format (HTML or PDF) with the following information:

- Vulnerability type and description
- Affected URLs or endpoints
- Payloads or actions used
- Severity levels
- AI-validated confidence rating
- Suggested remediation steps
- AI summary and code reasoning (when applicable)

Reports are automatically stored and timestamped for recordkeeping and analysis.

---

## System Design

The scanner is divided into five major layers:

1. **Target Handler**: Manages the target URL, handles normalization, redirect-following, and sitemap generation.
2. **Module Engine**: Loads and executes vulnerability-specific scanner modules.
3. **Result Collector**: Aggregates outputs from all active modules into a temporary result pool.
4. **AI Validator**: Processes raw results through an LLM and applies context-aware reasoning.
5. **Report Generator**: Formats validated results into structured, presentable formats with metadata.It generates two reports one validate and other raw.

Each module is independent but interacts with shared core utilities for logging, payload generation, and HTTP interaction.

---

## AI Integration Strategy

The validation logic leverages large language models through APIs or local inference tools like LM Studio. The validation module is abstracted to support multiple backends, including OpenAI, local GGUF models, or HuggingFace-hosted models.

The AI model is prompted with:

- Contextual payloads
- Observed behavior
- Target application response bodies
- Source code (if obtained from crawlers or plugins)

This enables the AI to assess the exploitability of findings beyond what static rules can detect.

---

## Intended Use Cases

- **Security Analysts**: Reduce time spent reviewing false positives by letting the AI filter results.
- **CTF Builders**: Customize or create intentional vulnerabilities for testing and challenge creation.
- **Pentesters**: Use as a first-pass reconnaissance and validation tool.
- **Bug Bounty Hunters**: Validate suspected vulnerabilities before reporting to programs.
- **Developers**: To test and secure applications locally.

---

## Planned Improvements

The project is under active development. Some of the enhancements planned include:

- Containerization with Docker for easy deployment
- API version for CI/CD integration
- Passive scanning of JavaScript behavior
- Integration with Burp Suite and ZAP as a plugin
- Addition of mobile-specific scanning modules (e.g., WebViews)

---

## Limitations

- AI validation accuracy depends on model choice and prompt quality.
- Some dynamic vulnerabilities (e.g., authentication bypasses) may require manual intervention.
- For advanced WAF-protected targets, evasion techniques may need to be applied externally.
- Yet to add authenticated scans.

---

## Contact

For questions, feedback, or collaboration, please reach out via GitHub Issues or open a discussion thread in the project repository.

---
## Contributor Socials 

### LinkedIN 
- https://www.linkedin.com/in/yash-radhakrishna/
- https://www.linkedin.com/in/aarti-korhale-67487824a/
- https://www.linkedin.com/in/yashwardhan-bhosale-335592298/

### Github
- https://github.com/Yashwardhan2512
- https://github.com/123yash8/
- https://github.com/AartiKorhale



