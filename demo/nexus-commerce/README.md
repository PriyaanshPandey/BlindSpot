# Nexus Commerce (Demo Target Application)

This is the controlled demonstration e-commerce store used to validate **Hidden Dependency X-Ray (HDX)**.

## Architectural Composition
- **Declared Services**: Express API, Stripe Payments, Auth0 Identity, AWS CloudFront CDN.
- **Seeded Discrepancy**: Undocumented third-party script calling `https://telemetry.untrusted-cdn.net` injected inside `frontend/checkout.js`.
- **Seeded Vulnerability**: `event-stream@3.3.6` containing malicious transitive dependency `flatmap-stream` (`GHSA-mh6f-8j2x-4483`). Static presence in manifests/lockfiles identifies historical supply-chain compromise but does not prove runtime execution.

## Verifying with HDX
When scanned with HDX:
1. Static analysis reveals declared packages and cloud infrastructure.
2. Runtime trace analysis flags `telemetry.untrusted-cdn.net` as an **undeclared endpoint discrepancy**.
3. Security analysis detects `event-stream@3.3.6` and `flatmap-stream@0.1.1` as **critical compromised packages** (`GHSA-mh6f-8j2x-4483`), distinguishing static presence from active execution.

