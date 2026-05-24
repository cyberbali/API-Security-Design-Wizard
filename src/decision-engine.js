// The security decision engine that evaluates user choices and maps them to recommendations.

export function evaluateSecurityProfile(answers) {
    const recommendations = {
        callers: {},
        authz: {},
        crossCutting: {},
        threats: [],
        riskScore: 0,
        riskRating: 'MINIMAL',
        mitigationChecklist: []
    };

    if (!answers) return recommendations;

    // 1. Calculate Risk Score based on Callers, Protection Level, and Attacker Goals
    let score = 0;
    
    // Callers count/sensitivity
    if (answers.callers) {
        score += answers.callers.length * 1.5;
    }
    
    // Protection Level Weight
    const protectionWeights = {
        'public': 1,
        'internal': 3,
        'sensitive': 6,
        'critical': 9
    };
    const protectionLevel = answers.protection_level || 'public';
    score += protectionWeights[protectionLevel];

    // Attacker Goals Count
    if (answers.attacker_goals) {
        score += answers.attacker_goals.length * 0.8;
    }

    // Cap score at 10
    recommendations.riskScore = Math.min(10, Math.round(score * 10) / 10);
    
    // Set Rating Label
    if (recommendations.riskScore <= 3) {
        recommendations.riskRating = 'MINIMAL';
    } else if (recommendations.riskScore <= 5.5) {
        recommendations.riskRating = 'LOW';
    } else if (recommendations.riskScore <= 8) {
        recommendations.riskRating = 'MEDIUM';
    } else {
        recommendations.riskRating = 'HIGH';
    }

    // 2. Authentication Recommendations per Caller
    if (answers.callers) {
        answers.callers.forEach(caller => {
            if (caller === 'human_browser') {
                const firstParty = answers.human_first_party || 'first_party';
                const clientTech = answers.human_client_tech || 'spa';
                
                if (firstParty === 'first_party') {
                    if (clientTech === 'server_rendered') {
                        recommendations.callers['human_browser'] = {
                            title: 'Server-Rendered First-Party Web App',
                            mechanism: 'Opaque Session Cookies (HttpOnly, Secure, SameSite=Lax)',
                            reasoning: 'Since the server controls the render cycle, a stateful server-side session cookie is the most secure pattern. JavaScript cannot read a Cookie with the HttpOnly flag, completely mitigating token exfiltration via XSS.',
                            threatsMitigated: ['XSS token theft (mitigated via HttpOnly)', 'CSRF (mitigated via SameSite=Lax & Double Submit CSRF Tokens)'],
                            implementation: 'Use memory-backed or Redis-backed sessions. Avoid encoding user IDs or JWTs in the session cookie. Short idle timeout (30 mins).'
                        };
                    } else {
                        recommendations.callers['human_browser'] = {
                            title: 'Single-Page Application (SPA)',
                            mechanism: 'Short-Lived Access Token in JS Memory + HttpOnly Refresh Cookie with PKCE',
                            reasoning: 'Because there is no server-side rendered state, storing access tokens in localStorage makes them vulnerable to XSS. Storing them strictly in JS memory (module state) and maintaining the session via an HttpOnly refresh cookie is the industry standard for SPAs.',
                            threatsMitigated: ['LocalStorage XSS theft', 'Authorization code interception (mitigated via PKCE)'],
                            implementation: 'Access tokens should expire in 15 minutes. Use OAuth 2.0 Authorization Code Flow with PKCE for silent refresh.'
                        };
                    }
                } else {
                    recommendations.callers['human_browser'] = {
                        title: 'Third-Party Web Client',
                        mechanism: 'OAuth 2.0 Authorization Code Flow + PKCE',
                        reasoning: 'Third-party integrations require user delegation without sharing credentials. The client web app uses PKCE (Proof Key for Code Exchange) to prevent authorization code interception.',
                        threatsMitigated: ['Credential sharing', 'Authorization code replay'],
                        implementation: 'Validate Redirect URIs against a strict whitelist. Enforce HTTPS only. Never return tokens in URL fragments.'
                    };
                }
            }

            if (caller === 'human_mobile') {
                recommendations.callers['human_mobile'] = {
                    title: 'Human via Native Mobile App',
                    mechanism: 'OAuth 2.0 Authorization Code Flow + PKCE + Secure OS Storage',
                    reasoning: 'Mobile binaries can be decompiled, meaning they cannot securely hold client secrets. Thus, they must use PKCE and leverage OS-level keychain/keystore to store cryptographic access tokens.',
                    threatsMitigated: ['Decompiled client secret leakage', 'Weak local storage token theft'],
                    implementation: 'Store tokens in iOS Keychain / Android KeyStore. Never write keys to local app preference files.'
                };
            }

            if (caller === 'machine_internal') {
                const securityBar = answers.machine_security_bar || 'standard';
                const hasUserContext = answers.machine_context === 'user_delegated';

                if (hasUserContext) {
                    recommendations.callers['machine_internal'] = {
                        title: 'Internal Machine-to-Machine with User Context',
                        mechanism: 'Token Forwarding or RFC 8693 Token Exchange',
                        reasoning: 'When calling downstream internal services on behalf of a user, services must forward the original user context or exchange it for a narrow-scoped token rather than calling using their own service permissions.',
                        threatsMitigated: ['Broad service scope privilege escalation', 'Lack of user accountability in microservices'],
                        implementation: 'Propagate the verified JWT downstream, or invoke a token exchange service to fetch service-specific scoped tokens.'
                    };
                } else if (securityBar === 'standard') {
                    recommendations.callers['machine_internal'] = {
                        title: 'Standard Service Identity (No User Context)',
                        mechanism: 'OAuth 2.0 Client Credentials Flow',
                        reasoning: 'For service-to-service calls where mTLS is overkill, standard client credentials (client_id/client_secret) stored in secure environments is standard practice.',
                        threatsMitigated: ['Hardcoded credentials in source code (via Secrets Manager)'],
                        implementation: 'Store client_secret in Vault, AWS Secrets Manager, or Env variables. Rotate credentials quarterly.'
                    };
                } else if (securityBar === 'high_assurance') {
                    recommendations.callers['machine_internal'] = {
                        title: 'High-Assurance Workloads',
                        mechanism: 'Mutual TLS (mTLS) with Internal CA',
                        reasoning: 'In zero-trust topologies, service identities are bound to ephemeral X.509 certificates. Gateway or service meshes validate both connection authenticity and identity at the network/transport layer.',
                        threatsMitigated: ['Leaked symmetric API keys / secrets', 'Spoofing internal IP ranges'],
                        implementation: 'Automate certificate issuance and renewal via SPIFFE/SPIRE or cert-manager (Kubernetes).'
                    };
                } else {
                    recommendations.callers['machine_internal'] = {
                        title: 'Very High Assurance (Financial / Healthcare Mesh)',
                        mechanism: 'Private Key JWT client_assertion + mTLS Transport',
                        reasoning: 'Provides a double-layer of security: mTLS secures the transport/network identity, while asymmetric Private Key JWT (RFC 7523) assertions establish application identity during token exchanges.',
                        threatsMitigated: ['Transport intercepts', 'Credential spoofing in high-value meshes'],
                        implementation: 'Machine signs a JWT with its private key as client_assertion to request short-lived access tokens.'
                    };
                }
            }

            if (caller === 'machine_thirdparty') {
                const integrationTech = answers.thirdparty_bar || 'api_keys';

                if (integrationTech === 'api_keys') {
                    recommendations.callers['machine_thirdparty'] = {
                        title: 'Third Party Integration (Simple API Keys)',
                        mechanism: 'Opaque Prefixed API Keys (Headers Only)',
                        reasoning: 'For simple API integrations where OAuth is a friction point, highly-random, secure API keys are acceptable. Keys must be stored hashed in the registry.',
                        threatsMitigated: ['Registry leak compounding (mitigated via hashing)', 'GitHub secret scanner commits (mitigated via prefix sk_live_)'],
                        implementation: 'Generate 256-bit random keys. Prefix keys (e.g. sk_live_). Always read from Custom Headers (e.g., X-API-Key), never URL parameters.'
                    };
                } else if (integrationTech === 'client_credentials') {
                    recommendations.callers['machine_thirdparty'] = {
                        title: 'Third Party Integration (OAuth 2.0 CC Flow)',
                        mechanism: 'OAuth 2.0 Client Credentials Flow with Scoped Tokens',
                        reasoning: 'Provides standard OAuth client integration where external partners exchange symmetric secrets for short-lived (e.g. 1 hour) access tokens that are auditable, scoped, and easily revocable.',
                        threatsMitigated: ['Permanent secret exposure on networks', 'Lack of auditing capacity'],
                        implementation: 'Deploy an Identity Server (e.g. Okta, Keycloak). Issue client_id & client_secret to partner, rotate scheduled.'
                    };
                } else {
                    recommendations.callers['machine_thirdparty'] = {
                        title: 'Third Party Integration (mTLS)',
                        mechanism: 'Mutual TLS (mTLS) with Partner CA Pinning',
                        reasoning: 'For high-assurance external integrations (e.g. clearinghouses, payment networks), transport security requires client certificate exchange whitelisted at the gateway layer.',
                        threatsMitigated: ['DNS spoofing', 'Bypassing API Gateway layers'],
                        implementation: 'Pin client certificates or use a dedicated partner PKI to establish transport authority.'
                    };
                }
            }
        });
    }

    // 3. Authorization Recommendations
    const dims = answers.authz_dimensions || [];
    
    if (dims.length === 1 && dims.includes('role')) {
        recommendations.authz = {
            modelName: 'Role-Based Access Control (RBAC)',
            desc: 'Job-function determines endpoint access. Simple, structured, and easily auditable. Best when user roles are stable and under ~20.',
            principles: [
                'Map actions to roles (e.g. soc_analyst can read_findings, team_lead can view_metrics).',
                'Roles are embedded in verified claims (JWT) and validated in controller middlewares.',
                'WARNING: RBAC alone does not prevent BOLA (Broken Object Level Authorization). You must layer resource-ownership checks.'
            ]
        };
    } else if (dims.length === 1 && dims.includes('attribute')) {
        recommendations.authz = {
            modelName: 'Attribute-Based Access Control (ABAC)',
            desc: 'Access determined by multi-dimensional policy evaluations (user clearance, classification, environment state, time-of-day).',
            principles: [
                'Create a centralized Policy Decision Point (PDP) using engines like Open Policy Agent (OPA).',
                'Pass attributes of user, resource, environment and action into policies.',
                'Establish strict unit tests on policies to prevent policy sprawl and edge-case leaks.'
            ]
        };
    } else if (dims.length === 1 && dims.includes('relationship')) {
        recommendations.authz = {
            modelName: 'Relationship-Based Access Control (ReBAC)',
            desc: 'Access is determined by user-to-resource graph relationships (e.g. user is a reviewer of Document A). Best for collaborative assets.',
            principles: [
                'Model access permissions as relationships on a directed graph.',
                'Enable permission inheritance (e.g., project members inherit view rights to all child files).',
                'Implement active caching on graph traversals to avoid database query bottlenecks.'
            ]
        };
    } else if (dims.length > 1) {
        recommendations.authz = {
            modelName: 'Hybrid Authorization Model',
            desc: 'A robust combination of Coarse Scopes, Role checks (RBAC), and Fine-Grained Object checks (Tenancy/Ownership). This is the gold-standard for production enterprise APIs.',
            principles: [
                'Layer 1: Coarse checks at API Gateway or Controller entry (e.g., has scope "read:findings" or role "soc_analyst").',
                'Layer 2: Fine-grained checks in DB fetch / Service layer (e.g., verify tenant_id or resource owner ID).',
                'Layer 3: Evaluate business-logic state (e.g., is finding already closed?).'
            ]
        };
    } else {
        recommendations.authz = {
            modelName: 'Scope-Based Access Control (OAuth Scopes)',
            desc: 'Coarse-grained operational access. Best for machine-to-machine APIs and third-party developer integrations.',
            principles: [
                'Embed scopes within the access token (e.g. scope: "read:findings").',
                'The resource server inspects and enforces scopes on endpoints.',
                'Scopes are coarse: "Can client perform type X operation?" but NOT "Can client access resource ID 9999?".'
            ]
        };
    }

    // Tenant Isolation Recommendations
    recommendations.authz.isMultiTenant = (answers.is_multitenant === 'yes');
    recommendations.authz.hasAdminEndpoints = (answers.function_protection === 'yes');

    // 4. Cross-Cutting Strategy Recommendations
    const accessLifetime = answers.access_lifetime || '15m';
    const refreshLifetime = answers.refresh_lifetime || '7d';
    const immediateRevocation = (answers.immediate_revocation === 'yes');

    let tokenStrategy = `Access Token Lifetime: ${accessLifetime}. `;
    if (answers.callers && (answers.callers.includes('human_browser') || answers.callers.includes('human_mobile'))) {
        tokenStrategy += `Refresh Token Lifetime: ${refreshLifetime} with active rotation (rotate refresh tokens on every single use).`;
    } else {
        tokenStrategy += 'Machine API tokens: Short-lived access tokens, no refresh tokens needed (machines can call token endpoint directly using secrets).';
    }

    let revocationStrategy = '';
    if (immediateRevocation) {
        revocationStrategy = 'Because immediate revocation is required, use Opaque Sessions in Redis (for Browser session clients) or JWT with active JTI Deny List in Redis. Verify token ID (jti) against the Redis database on every protected endpoint.';
    } else {
        revocationStrategy = 'Standard revocation: Revoking refresh tokens stops new access tokens from being issued. Access tokens expire naturally in 15 minutes, which represents the maximum window of risk in case of a token leak.';
    }

    recommendations.crossCutting = {
        tokenStrategy,
        revocationStrategy,
        complianceRequirements: answers.regulatory_context || 'none',
        auditLogging: answers.audit_logging || []
    };

    // 5. Build Attacker Checklist based on Realistic Scenarios
    if (answers.attacker_goals) {
        answers.attacker_goals.forEach(goal => {
            let threatObj = {};
            if (goal === 'impersonate_user') {
                threatObj = {
                    title: 'Attacker Impersonates a Specific User',
                    impact: 'Attacker gains access to a targeted user\'s files and resources.',
                    mitigations: [
                        'Enforce Multi-Factor Authentication (MFA) on logins.',
                        'Design short access token lifetimes (15 minutes maximum).',
                        'Use anomaly detection (e.g., concurrent sessions from different countries).'
                    ]
                };
            } else if (goal === 'impersonate_app') {
                threatObj = {
                    title: 'Attacker Impersonates the Application Client',
                    impact: 'Attacker steals client secrets to request tokens directly, bypassing standard flows.',
                    mitigations: [
                        'Store client secrets exclusively in secure Key Vaults/Secrets Managers, never in code.',
                        'Rotate service credentials regularly (automated rotations quarterly).',
                        'For high-security services, switch to Private Key JWT assertions (RFC 7523) or mTLS.'
                    ]
                };
            } else if (goal === 'escalate_privilege') {
                threatObj = {
                    title: 'Attacker Escalates Privileges (BOLA / IDOR / BFLA)',
                    impact: 'Low-privilege user exfiltrates other users\' data or accesses admin endpoints.',
                    mitigations: [
                        'Always fetch Tenant ID and User ID from the cryptographically verified token claims, never from user input (body or URL).',
                        'Verify resource ownership (e.g. object.userId == token.userId) at the DB query or service boundary.',
                        'Ensure admin paths (/api/admin/*) require explicit elevated role check middlewares.'
                    ]
                };
            } else if (goal === 'abuse_scale') {
                threatObj = {
                    title: 'Attacker Abuses Valid Credentials at Scale',
                    impact: 'Data scraping, denial of service, resource exhaustion, or credential stuffing.',
                    mitigations: [
                        'Implement endpoint-specific rate limiting (e.g., strict limits on auth/login paths).',
                        'Restrict API scope sizes: tokens must only contain the absolute minimum scopes needed.',
                        'Monitor volumetric anomalies in SIEM dashboards (e.g., massive spike in 404s or data bytes).'
                    ]
                };
            } else if (goal === 'persist_rotation') {
                threatObj = {
                    title: 'Attacker Persists Access After Credential Rotation',
                    impact: 'Attacker plants backdoors or maintains API access even after password resets.',
                    mitigations: [
                        'Maintain a robust audit log recording all user credential updates and new token creations.',
                        'Support instant JTI revocation in Redis: when passwords rotate, instantly blacklist active tokens.',
                        'Limit refresh token durations and force complete re-auth after a session timeout limit (e.g., 8 hours).'
                    ]
                };
            } else if (goal === 'pivot_system') {
                threatObj = {
                    title: 'Attacker Pivots Downstream via compromised service',
                    impact: 'Compromising a low-trust edge service grants entry to highly-privileged internal networks.',
                    mitigations: [
                        'Enforce network segmentation (Kubernetes NetworkPolicies).',
                        'Never reuse edge credentials downstream: use Token Forwarding or Token Exchange (RFC 8693).',
                        'Maintain narrow scopes on service-to-service tokens (e.g., billing-service only has read:billing).'
                    ]
                };
            }
            recommendations.threats.push(threatObj);
        });
    }

    // 6. Build Failure Modes & Resiliency Strategy (Phase 1, Q5)
    recommendations.failureModes = [];
    const callersList = answers.callers || [];

    // All architectures have AuthZ rules that could be misconfigured
    recommendations.failureModes.push({
        title: 'Authorization Rule Misconfigured / BOLA',
        blastRadius: 'Attacker bypasses resource checks, exfiltrating data belonging to other tenants or users.',
        mitigation: 'Implement strict unit tests for access rules, automate integration tests simulating cross-tenant violations (asserting 404 responses), and enforce mandatory security linting on database repository wrappers.'
    });

    // If SPA or mobile is used, token stolen from storage is realistic
    if ((callersList.includes('human_browser') && answers.human_client_tech === 'spa') || callersList.includes('human_mobile')) {
        recommendations.failureModes.push({
            title: 'Access Token Stolen from Client Local Storage',
            blastRadius: 'Bearer credential is fully usable by the attacker until its natural expiration (exfiltration via XSS).',
            mitigation: 'Never store access tokens in localStorage or sessionStorage. Maintain them strictly in JavaScript module-level memory, and handle sessions via HttpOnly SameSite=Strict cookies. Design access token expirations under 15 minutes.'
        });
    }

    // If using JWTs (like SPA browser, mobile, token-forwarding, or client credentials mesh)
    const usesJWT = (callersList.includes('human_browser') && answers.human_client_tech === 'spa') || 
                    (callersList.includes('human_mobile')) || 
                    (callersList.includes('machine_internal')) || 
                    (callersList.includes('machine_thirdparty') && answers.thirdparty_bar === 'client_credentials');
                    
    if (usesJWT) {
        recommendations.failureModes.push({
            title: 'JWT Secret Key / Signing Certificate Leaked',
            blastRadius: 'Attacker can forge any token, granting them complete, administrative access to the API.',
            mitigation: 'Configure automated, scheduled signing key rotations via JWKS endpoints. Maintain an active, Redis-backed JTI blocklist to invalidate compromised tokens instantly.'
        });
    }

    // If using API keys
    if (callersList.includes('machine_thirdparty') && answers.thirdparty_bar === 'api_keys') {
        recommendations.failureModes.push({
            title: 'Symmetric API Key Leaked / Committed to Source Control',
            blastRadius: 'Permanent, unauthorized impersonation of the associated third-party partner.',
            mitigation: 'Always store API keys cryptographically hashed in your registry using SHA-256 (never in cleartext). Enforce "sk_live_" prefixes on keys to trigger automated GitHub/GitLab secret scanning blocks.'
        });
    }

    // If using OAuth flow or client secrets
    const usesClientSecret = (callersList.includes('human_browser') && answers.human_first_party === 'third_party') || 
                             (callersList.includes('machine_internal') && answers.machine_security_bar === 'standard') ||
                             (callersList.includes('machine_thirdparty') && answers.thirdparty_bar === 'client_credentials');

    if (usesClientSecret) {
        recommendations.failureModes.push({
            title: 'OAuth Client Secret Leaked',
            blastRadius: 'Attacker can impersonate the client application, request tokens, and perform unauthorized back-channel actions.',
            mitigation: ' secrets must reside in secure Key Vaults (AWS Secrets Manager, HashiCorp Vault), never in code bases. Instantly revoke compromised client_ids. Upgrade to Private Key JWT assertions (client_assertion).'
        });
    }

    // If using an IdP (OIDC, standard OAuth, Okta)
    const usesIdP = (callersList.includes('human_browser') && answers.human_first_party === 'third_party') ||
                    (callersList.includes('human_mobile')) ||
                    (callersList.includes('machine_internal') && answers.machine_security_bar === 'standard');

    if (usesIdP) {
        recommendations.failureModes.push({
            title: 'Central Identity Provider (IdP) Goes Down',
            blastRadius: 'Single point of failure. All authentication fails and completely blocks system access.',
            mitigation: 'Design for highly cached, local JWKS cached verification. Implement local fallback JWKS storage and configure IdP redundancy.'
        });
    }

    return recommendations;
}
