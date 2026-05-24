// Structured questions database for the Threat Modelling and Auth Decision Wizard

export const phases = [
    { id: 'threat-model', name: 'Phase 1: Threat Modelling' },
    { id: 'authn', name: 'Phase 2: Authentication' },
    { id: 'authz', name: 'Phase 3: Authorization' },
    { id: 'cross-cutting', name: 'Phase 4: Cross-Cutting' }
];

export const questions = [
    {
        id: 'welcome',
        phase: 'threat-model',
        title: 'API Security Design Wizard',
        subtitle: 'Configure your security context, walk the decision trees, and generate a customized Security Architecture Design Document.',
        type: 'welcome'
    },
    // ==========================================
    // PHASE 1: THREAT MODELLING QUESTIONS
    // ==========================================
    {
        id: 'callers',
        phase: 'threat-model',
        title: 'Who Are the Callers?',
        subtitle: 'Every other decision flows from who is calling your API. Mixed caller scenarios are walked one-by-one.',
        type: 'checkbox',
        options: [
            {
                value: 'human_browser',
                label: 'Human via Browser',
                icon: 'fa-desktop',
                desc: 'A person interacting through a web application. They expect a login flow and can perform Multi-Factor Authentication.',
                threat: 'Session hijacking, XSS stealing tokens, CSRF attacks, credential stuffing.'
            },
            {
                value: 'human_mobile',
                label: 'Human via Mobile App',
                icon: 'fa-mobile-screen-button',
                desc: 'A person on a native iOS or Android app. Cannot hold a client secret securely (anyone can decompile the binary).',
                threat: 'Token theft from device, lack of PKCE, weak storage.'
            },
            {
                value: 'machine_internal',
                label: 'Machine - Your Services',
                icon: 'fa-server',
                desc: 'An automated process you control: background jobs, microservices, pipeline. Uses its own service identity.',
                threat: 'Leaked service credentials giving full service identity.'
            },
            {
                value: 'machine_thirdparty',
                label: 'Machine - Third Party',
                icon: 'fa-hands-holding-child',
                desc: 'An external system operated by a partner or third-party developer. Secrets may leak; you don\'t control their infrastructure.',
                threat: 'Impersonation via leaked API key or client credentials.'
            }
        ],
        validate: (answers) => answers.callers && answers.callers.length > 0 ? null : 'Please select at least one caller type.'
    },
    {
        id: 'protection_level',
        phase: 'threat-model',
        title: 'What Is Being Protected?',
        subtitle: 'Resource value determines the level of proportionate investment in security controls. Over-engineering is waste; under-engineering is a breach.',
        type: 'radio',
        options: [
            {
                value: 'public',
                label: 'Public',
                icon: 'fa-globe',
                desc: 'No harm if anyone reads it.',
                example: 'Health checks, public documentation, open datasets. Authentication may not be required for reads.'
            },
            {
                value: 'internal',
                label: 'Internal',
                icon: 'fa-network-wired',
                desc: 'Legitimate internal use only. Not public, but not catastrophic if leaked.',
                example: 'Internal metrics, non-PII operational data. Basic authentication required.'
            },
            {
                value: 'sensitive',
                label: 'Sensitive',
                icon: 'fa-user-lock',
                desc: 'PII, business-confidential data, security findings, credentials. Leak causes regulatory or reputational harm.',
                example: 'Strong authentication and fine-grained authorization required.'
            },
            {
                value: 'critical',
                label: 'Critical',
                icon: 'fa-triangle-exclamation',
                desc: 'Admin functions, credential management, bulk data export, configuration changes.',
                example: 'Compromises entire system. Strongest controls, MFA, audit logging, step-up auth required.'
            }
        ]
    },
    {
        id: 'attacker_goals',
        phase: 'threat-model',
        title: 'What Does the Attacker Actually Want?',
        subtitle: 'Specific attacker goals determine which controls matter. Select realistic threat scenarios for your system.',
        type: 'checkbox',
        options: [
            {
                value: 'impersonate_user',
                label: 'Impersonate a Specific User',
                icon: 'fa-user-ninja',
                desc: 'Steal one account\'s token or credential.',
                mitigation: 'Short token lifetime, MFA, anomaly detection.'
            },
            {
                value: 'impersonate_app',
                label: 'Impersonate the Application',
                icon: 'fa-robot',
                desc: 'Steal the client secret or forge a service token (e.g. against M2M APIs).',
                mitigation: 'Secrets manager, mTLS, client assertions.'
            },
            {
                value: 'escalate_privilege',
                label: 'Escalate Privilege Within System',
                icon: 'fa-arrow-up-wide-short',
                desc: 'Use low-privilege accounts to access high-privilege resources (BOLA, IDOR, broken authZ).',
                mitigation: 'Fine-grained authZ, object-level access checks.'
            },
            {
                value: 'abuse_scale',
                label: 'Abuse Legitimate Access at Scale',
                icon: 'fa-gauge-high',
                desc: 'Use valid credentials to scrape data, credential stuff other accounts, or exhaust resources.',
                mitigation: 'Rate limiting, anomaly detection, scope minimization.'
            },
            {
                value: 'persist_rotation',
                label: 'Persist After Credential Rotation',
                icon: 'fa-clock-rotate-left',
                desc: 'Plant backdoors, create secondary credentials, maintain access after breach detection.',
                mitigation: 'Audit logging, short-lived tokens, jti revocation.'
            },
            {
                value: 'pivot_system',
                label: 'Pivot to Adjacent Systems',
                icon: 'fa-shuffle',
                desc: 'Use API access as a stepping stone. Realistic when the API calls downstream services with elevated privilege.',
                mitigation: 'Least-privilege tokens, service-specific scopes, network segmentation.'
            }
        ]
    },
    {
        id: 'operational_env',
        phase: 'threat-model',
        title: 'Operational Environment & Constraints',
        subtitle: 'Controls that work perfectly on paper fail in practice due to operational limits. Outline your environment constraints.',
        type: 'multi_question',
        questions: [
            {
                id: 'can_hold_secret',
                label: 'Can the clients hold secrets securely?',
                type: 'select',
                options: [
                    { value: 'yes', label: 'Yes (Server-side apps, backend-to-backend)' },
                    { value: 'no', label: 'No (Mobile apps, SPAs, IoT, CLI tools)' }
                ]
            },
            {
                id: 'browser_available',
                label: 'Is there a browser redirect context available?',
                type: 'select',
                options: [
                    { value: 'yes', label: 'Yes (Web app with redirection/login UI)' },
                    { value: 'no', label: 'No (CLI, background service, microservice mesh)' }
                ]
            },
            {
                id: 'verifiers_count',
                label: 'How many services need to verify authentication tokens?',
                type: 'select',
                options: [
                    { value: 'one', label: 'Only one (Monolith API gateway / Single backend)' },
                    { value: 'many', label: 'Many services (Microservices mesh, distributed architecture)' }
                ]
            },
            {
                id: 'immediate_revocation',
                label: 'Is immediate real-time credential revocation required?',
                type: 'select',
                options: [
                    { value: 'no', label: 'No (Can wait up to 1 hour for access tokens to expire naturally)' },
                    { value: 'yes', label: 'Yes (Must be able to instantly revoke a session/token)' }
                ]
            }
        ]
    },
    {
        id: 'regulatory_context',
        phase: 'threat-model',
        title: 'Regulatory & Compliance Context',
        subtitle: 'Select the compliance frameworks governing your system to map mandatory controls and audit targets.',
        type: 'checkbox',
        options: [
            {
                value: 'none',
                label: 'No Specific Compliance',
                icon: 'fa-globe',
                desc: 'Standard security guidelines. Suitable for general-purpose web APIs without strict regulatory audits.'
            },
            {
                value: 'soc2',
                label: 'SOC 2 / ISO 27001',
                icon: 'fa-certificate',
                desc: 'Enforces auditable access logging, multi-factor authentication (MFA) policies, and regular credential rotation.'
            },
            {
                value: 'hipaa',
                label: 'HIPAA / FedRAMP',
                icon: 'fa-file-shield',
                desc: 'Requires high-security tenant isolation, strict session timeouts, detailed UTC audit trails, and mandatory MFA.'
            },
            {
                value: 'psd2',
                label: 'PSD2 / Open Banking',
                icon: 'fa-building-columns',
                desc: 'Demands Strong Customer Authentication (SCA), transaction-level step-up auth, and high assurance validation (mTLS).'
            },
            {
                value: 'pci_dss',
                label: 'PCI-DSS (Payment Cards)',
                icon: 'fa-credit-card',
                desc: 'Mandates cardholder data tokenization, PAN masking, TLS 1.3 encryption, and robust MFA for payment networks.'
            },
            {
                value: 'isa_62443',
                label: 'ISA 62443 (Industrial OT)',
                icon: 'fa-industry',
                desc: 'Industrial Automation and Control Systems. Focuses on conduit zone isolation, mTLS, and zero human interfaces.'
            }
        ]
    }
];

// ==========================================
// PHASE 2: AUTHENTICATION BRANCHES
// ==========================================

export const authnHumanQuestions = [
    {
        id: 'human_first_party',
        title: 'Human Caller: Is this a first-party application?',
        subtitle: 'Determines if you need a full OAuth delegation flow or if direct, native authentication is more appropriate.',
        type: 'radio',
        options: [
            {
                value: 'first_party',
                label: 'Yes — First Party',
                icon: 'fa-shield-halved',
                desc: 'Your own frontend calling your own backend API. No third-party delegation needed.'
            },
            {
                value: 'third_party',
                label: 'No — Third Party / External App',
                icon: 'fa-handshake',
                desc: 'An external client requesting access to your user\'s resources. OAuth 2.0 Authorization Code Flow is required.'
            }
        ]
    },
    {
        id: 'human_client_tech',
        title: 'Human Caller: Frontend Client Architecture',
        subtitle: 'The engineering design changes drastically depending on where the user context and sessions are managed.',
        type: 'radio',
        options: [
            {
                value: 'server_rendered',
                label: 'Server-Rendered Web App',
                icon: 'fa-cubes',
                desc: 'Backend controls the session. Browser handles opaque session cookies, which JavaScript cannot access.'
            },
            {
                value: 'spa',
                label: 'Single-Page Application (SPA)',
                icon: 'fa-code',
                desc: 'Client-side SPA (React, Vue, Angular). Opaque sessions aren\'t natively held; JWTs are stored in JS memory.'
            }
        ],
        condition: (answers) => answers.human_first_party === 'first_party'
    },
    {
        id: 'human_mfa_requirement',
        title: 'MFA — When Is Multi-Factor Authentication Required?',
        subtitle: 'MFA is a policy decision sitting on top of your authentication mechanism. When must it be enforced?',
        type: 'checkbox',
        options: [
            {
                value: 'admin_ops',
                label: 'Always for Admin Operations',
                icon: 'fa-user-gear',
                desc: 'Creating/deleting users, changing permissions, bulk export, configuration changes.'
            },
            {
                value: 'step_up',
                label: 'Step-up Auth for Sensitive Actions',
                icon: 'fa-shield-heart',
                desc: 'User is authenticated, but triggers a fresh MFA challenge for high-value actions (e.g. transfers).'
            },
            {
                value: 'risk_based',
                label: 'Risk-Based / Contextual MFA',
                icon: 'fa-user-secret',
                desc: 'New device, new location, unusual hours, or anomalous API calling patterns.'
            }
        ]
    }
];

export const authnMachineQuestions = [
    {
        id: 'machine_context',
        title: 'Machine Caller: Is there a User Context?',
        subtitle: 'Is the service calling downstream acting on behalf of an authenticated user, or as its own service identity?',
        type: 'radio',
        options: [
            {
                value: 'user_delegated',
                label: 'Acting on Behalf of a User (Delegated Access)',
                icon: 'fa-user-check',
                desc: 'Downstream forwarding of user credentials. Requires token forwarding or RFC 8693 token exchange.'
            },
            {
                value: 'service_identity',
                label: 'Acting as Itself (Service Identity Only)',
                icon: 'fa-key',
                desc: 'No user context. Automated jobs, scheduled pipelines, microservice-to-microservice calls.'
            }
        ]
    },
    {
        id: 'machine_security_bar',
        title: 'Machine Caller: How High is the Security Bar?',
        subtitle: 'The communication environment determines the engineering requirements for machine authentication.',
        type: 'radio',
        options: [
            {
                value: 'standard',
                label: 'Standard Internal Services',
                icon: 'fa-shield-halved',
                desc: 'OAuth 2.0 Client Credentials Flow. Identifiers and secrets stored securely in Secrets Managers.'
            },
            {
                value: 'high_assurance',
                label: 'High-Assurance / Zero-Trust Mesh',
                icon: 'fa-network-wired',
                desc: 'Mutual TLS (mTLS). Identities are cryptographically tied to X.509 certificates validated on every connection.'
            },
            {
                value: 'very_high',
                label: 'Very High Assurance (Financial / Health)',
                icon: 'fa-building-shield',
                desc: 'Private Key JWT (client_assertion) for token exchange + mTLS for transport layer security. Double layer protection.'
            }
        ],
        condition: (answers) => answers.machine_context === 'service_identity'
    }
];

export const authnThirdPartyMachineQuestions = [
    {
        id: 'thirdparty_bar',
        title: 'Third Party Machine: Integration Architecture',
        subtitle: 'How complex is the third-party client integration, and what controls does your environment demand?',
        type: 'radio',
        options: [
            {
                value: 'api_keys',
                label: 'Opaque API Keys',
                icon: 'fa-key',
                desc: 'Simple API key verification (hashed at rest). Best for developer integrations without user delegation.'
            },
            {
                value: 'client_credentials',
                label: 'OAuth 2.0 Client Credentials Flow',
                icon: 'fa-shield',
                desc: 'Client exchanges credentials for scoped, short-lived tokens. Best for auditable and revocable machine access.'
            },
            {
                value: 'mtls_partner',
                label: 'mTLS Workload Federation',
                icon: 'fa-fingerprint',
                desc: 'Mutual TLS (mTLS) for high-assurance partners (financial, government, enterprise integrations).'
            }
        ]
    }
];

// ==========================================
// PHASE 3: AUTHORIZATION QUESTIONS
// ==========================================

export const authzQuestions = [
    {
        id: 'authz_dimensions',
        phase: 'authz',
        title: 'Understand Access Control Dimensions',
        subtitle: 'Select all variables that determine if an API request should be allowed or denied. These variables define your AuthZ model.',
        type: 'checkbox',
        options: [
            {
                value: 'role',
                label: 'Role-Based (RBAC)',
                icon: 'fa-user-tag',
                desc: 'Access is determined by the user\'s job function (e.g. Admin, Auditor, Analyst).'
            },
            {
                value: 'ownership',
                label: 'Resource Ownership',
                icon: 'fa-box-open',
                desc: 'Users can access resources they owned/created, but not other users\' resources.'
            },
            {
                value: 'tenant',
                label: 'Organization / Tenant',
                icon: 'fa-building',
                desc: 'In multi-tenant SaaS, users can only access data belonging to their specific organization.'
            },
            {
                value: 'attribute',
                label: 'Context-Aware Attributes (ABAC)',
                icon: 'fa-circle-info',
                desc: 'Access depends on environment, clearance, classification, time-of-day, or device status.'
            },
            {
                value: 'relationship',
                label: 'Relationship Graph (ReBAC)',
                icon: 'fa-diagram-project',
                desc: 'Access is inherited through structured relations (e.g. user is a member of Project A, which owns Finding X).'
            },
            {
                value: 'sensitivity',
                label: 'Action Sensitivity',
                icon: 'fa-heart-crack',
                desc: 'Different HTTP methods (GET vs DELETE) on the same object require different access levels.'
            }
        ],
        validate: (answers) => answers.authz_dimensions && answers.authz_dimensions.length > 0 ? null : 'Please select at least one access control dimension.'
    },
    {
        id: 'is_multitenant',
        phase: 'authz',
        title: 'Multi-Tenancy Isolation',
        subtitle: 'Multi-tenancy isolation is a first-class authorization requirement. Failing here results in catastrophic BOLA/IDOR vulnerabilities.',
        type: 'radio',
        options: [
            {
                value: 'yes',
                label: 'Yes, this is a multi-tenant application',
                icon: 'fa-people-roof',
                desc: 'Must enforce strict tenant boundary filtering at the database layer.'
            },
            {
                value: 'no',
                label: 'No, single-tenant or internal monolithic scope',
                icon: 'fa-person',
                desc: 'Resources are either globally public, shared, or simple user-level isolated.'
            }
        ]
    },
    {
        id: 'function_protection',
        phase: 'authz',
        title: 'Protecting Function-Level Access',
        subtitle: 'Even if object-level access is secure, administrative endpoints must be explicitly protected to prevent broken function-level auth (BFLA).',
        type: 'radio',
        options: [
            {
                value: 'yes',
                label: 'Yes, we have admin / config endpoints',
                icon: 'fa-screwdriver-wrench',
                desc: 'Endpoints like /api/admin/*, /api/internal/* require elevated role checks.'
            },
            {
                value: 'no',
                label: 'No, all callers access identical feature sets',
                icon: 'fa-circle-user',
                desc: 'Coarse user roles are unnecessary; standard user-level checks apply across all routes.'
            }
        ]
    }
];

// ==========================================
// PHASE 4: CROSS-CUTTING CONCERNS (RECOMMENDED RANGES / INPUTS)
// ==========================================

export const crossCuttingQuestions = [
    {
        id: 'token_lifetime_input',
        phase: 'cross-cutting',
        title: 'Define Token Lifetime Strategy',
        subtitle: 'Token lifetime is a risk parameter, not a convenience. Design short lifetimes to minimize compromise window.',
        type: 'multi_question',
        questions: [
            {
                id: 'access_lifetime',
                label: 'Access Token Lifetime',
                type: 'select',
                options: [
                    { value: '5m', label: '5 Minutes (Recommended for high security / admin operations)' },
                    { value: '15m', label: '15 Minutes (Standard recommendation for typical browser/mobile APIs)' },
                    { value: '1h', label: '1 Hour (Maximum recommended for server applications)' },
                    { value: '24h', label: '24 Hours (Long-lived - higher risk, requires robust revocation)' }
                ]
            },
            {
                id: 'refresh_lifetime',
                label: 'Refresh Token Lifetime (if applicable)',
                type: 'select',
                options: [
                    { value: '1d', label: '1 Day (Strict session constraints)' },
                    { value: '7d', label: '7 Days (Typical default, rotated on every use)' },
                    { value: '30d', label: '30 Days (Extended offline mobile access)' }
                ]
            }
        ]
    },
    {
        id: 'audit_logging',
        phase: 'cross-cutting',
        title: 'Audit Logging & Monitoring Strategy',
        subtitle: 'Every authN/Z success and failure must be logged. Good security relies on active detection and auditable logs.',
        type: 'checkbox',
        options: [
            {
                value: 'log_failures',
                label: 'Log AuthN/Z Failures (401 / 403 / 404)',
                icon: 'fa-user-xmark',
                desc: 'Log credential mismatches, role failures, and BOLA blocks (returning 404).'
            },
            {
                value: 'log_mfa',
                label: 'Log MFA and Administrative Actions',
                icon: 'fa-shield-halved',
                desc: 'Log password resets, key creations, role changes, and MFA events.'
            },
            {
                value: 'siem_feed',
                label: 'Feed Auth Logs to SIEM',
                icon: 'fa-chart-line',
                desc: 'Real-time alert indicators for credential stuffing and lateral movement.'
            }
        ]
    }
];
