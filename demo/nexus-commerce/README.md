# Nexus Commerce (Demo Target Application)

This is the controlled demonstration e-commerce store used to validate **Hidden Dependency X-Ray (HDX)**.

## Architectural Composition
- **Declared Services**: Express API, Stripe Payments, Auth0 Identity, AWS CloudFront CDN.
- **Seeded Discrepancy**: Undocumented third-party script calling `https://telemetry.untrusted-cdn.net` injected inside `frontend/checkout.js`.
- **Seeded Vulnerability**: `event-stream@3.3.6` containing malicious bitcoin wallet harvesting code (`CVE-2018-3721`).

## Verifying with HDX
When scanned with HDX:
1. Static analysis reveals declared packages and cloud infrastructure.
2. Runtime trace analysis flags `telemetry.untrusted-cdn.net` as an **undeclared endpoint discrepancy**.
3. Security analysis detects `event-stream@3.3.6` as a **critical compromised package**.

