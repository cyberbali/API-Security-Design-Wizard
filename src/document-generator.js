// Module responsible for generating the Markdown and HTML design documents.

export function generateSecurityDocumentHTML(answers, profile) {
    const callers = answers.callers || [];
    const compliance = profile.crossCutting.complianceRequirements.toUpperCase();
    const hasAuditLogs = profile.crossCutting.auditLogging && profile.crossCutting.auditLogging.length > 0;
    
    // Generate the SVG Architecture Diagram dynamically
    const svgDiagram = generateSVGDiagram(answers, profile);

    let html = `
        <div class="animate-fade-in">
            <h1>Security Architecture Design Document</h1>
            <p><em>Generated on: ${new Date().toLocaleDateString()} | System Risk Rating: <strong>${profile.riskRating}</strong></em></p>
            
            <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 2rem 0;">

            <!-- ==========================================
                 SECTION 1: EXECUTIVE SUMMARY
                 ========================================== -->
            <section id="doc-section-1">
                <h2><i class="fa-solid fa-gauge-high"></i> 1. Executive Summary & Threat Scorecard</h2>
                <p>This document details the Security Architecture Design (Authentication and Authorization strategy) for the target system. The specifications detailed here are derived dynamically using the security decision tree framework, aligning mechanisms directly to system threat exposure and operational constraints.</p>
                
                <div class="doc-scorecard-grid">
                    <div class="doc-scorecard-card">
                        <div class="doc-scorecard-value ${profile.riskScore >= 7.5 ? 'high-risk' : ''}">${profile.riskScore} / 10</div>
                        <div class="doc-scorecard-label">Threat Complexity Score</div>
                    </div>
                    <div class="doc-scorecard-card">
                        <div class="doc-scorecard-value" style="color: ${profile.riskRating === 'HIGH' ? 'var(--state-danger)' : (profile.riskRating === 'MEDIUM' ? 'var(--state-warning)' : 'var(--state-success)')}">${profile.riskRating}</div>
                        <div class="doc-scorecard-label">Overall Risk Category</div>
                    </div>
                    <div class="doc-scorecard-card">
                        <div class="doc-scorecard-value">${callers.length}</div>
                        <div class="doc-scorecard-label">Active Caller Interfaces</div>
                    </div>
                    <div class="doc-scorecard-card">
                        <div class="doc-scorecard-value" style="color: #c084fc;">${compliance}</div>
                        <div class="doc-scorecard-label">Compliance Profile</div>
                    </div>
                </div>

                <div class="doc-callout tip">
                    <h5><i class="fa-solid fa-circle-info"></i> Architectural Mandate</h5>
                    <p>Security mechanisms must always map to their specific context. Avoid selecting authentication mechanisms in isolation. Review the threat vectors in Section 2 and ensure the developers implement the exact middleware layering defined in Section 4.</p>
                </div>
            </section>

            <div class="doc-section-break"></div>

            <!-- ==========================================
                 SECTION 2: SYSTEM THREAT MODEL
                 ========================================== -->
            <section id="doc-section-2">
                <h2><i class="fa-solid fa-shield-halved"></i> 2. System Threat Model</h2>
                <p>An API threat model is the baseline for mechanism selection. Based on the callers and attacker profiles, the following threats are identified as highly realistic for this system.</p>

                <h3>2.1 User & Caller Attack Surfaces</h3>
                <ul>
                    ${callers.map(c => {
                        let desc = '';
                        let threats = '';
                        if (c === 'human_browser') {
                            desc = 'Human via Browser (Web client interaction).';
                            threats = 'Session hijacking, XSS (Cross-Site Scripting) stealing tokens, CSRF (Cross-Site Request Forgery) attacks, credential stuffing.';
                        } else if (c === 'human_mobile') {
                            desc = 'Human via Native Mobile App.';
                            threats = 'Token theft from local device, lack of PKCE resulting in authorization code interception, weak secure storage.';
                        } else if (c === 'machine_internal') {
                            desc = 'Machine-to-Machine Internal Service.';
                            threats = 'Leaked service credentials giving full service identity, broad downstream permissions without boundaries.';
                        } else if (c === 'machine_thirdparty') {
                            desc = 'Machine-to-Machine Third-Party Integration.';
                            threats = 'Impersonation via leaked partner API key, credential leak, lack of auditable logs on external actions.';
                        }
                        return `<li><strong>${desc}</strong><br><span style="color: var(--state-danger); font-size: 0.9em;"><i class="fa-solid fa-triangle-exclamation"></i> Primary threats: ${threats}</span></li>`;
                    }).join('')}
                </ul>

                <h3>2.2 Attacker Goals & Recommended Mitigations</h3>
                ${profile.threats.length === 0 ? '<p>No specific attacker goals selected. Default minimal controls apply.</p>' : 
                profile.threats.map(t => `
                    <div class="doc-callout warning">
                        <h5><i class="fa-solid fa-skull-crossbones"></i> Threat: ${t.title}</h5>
                        <p><strong>Potential Impact:</strong> ${t.impact}</p>
                        <p><strong>Mandatory Controls:</strong></p>
                        <ul style="margin-top: 0.5rem; margin-bottom: 0;">
                            ${t.mitigations.map(m => `<li>${m}</li>`).join('')}
                        </ul>
                    </div>
                `).join('')}
            </section>

            <div class="doc-section-break"></div>

            <!-- ==========================================
                 SECTION 3: AUTHENTICATION
                 ========================================== -->
            <section id="doc-section-3">
                <h2><i class="fa-solid fa-user-shield"></i> 3. Authentication (AuthN) Architecture</h2>
                <p>Authentication answers: <em>"Are you who you say you are?"</em>. Below is the custom design mapping every caller type to a robust authentication mechanism.</p>
                
                ${Object.keys(profile.callers).map(key => {
                    const c = profile.callers[key];
                    return `
                        <div class="doc-callout tip" style="border-left-color: var(--accent-cyan);">
                            <h5 style="color: var(--accent-cyan);"><i class="fa-solid fa-user-check"></i> Caller type: ${c.title}</h5>
                            <p><strong>Recommended Mechanism:</strong> <code style="font-size: 1rem; color: #ffffff; background: rgba(0,242,254,0.08); border-color: rgba(0,242,254,0.2);">${c.mechanism}</code></p>
                            <p><strong>Reasoning:</strong> ${c.reasoning}</p>
                            <p><strong>Implementation Strategy:</strong> ${c.implementation}</p>
                        </div>
                    `;
                }).join('')}

                ${answers.human_mfa_requirement && answers.human_mfa_requirement.length > 0 ? `
                    <h3>3.2 Multi-Factor Authentication (MFA) Policy</h3>
                    <p>MFA is enforced as a contextual policy layer over standard logins:</p>
                    <ul>
                        ${answers.human_mfa_requirement.map(mfa => {
                            if (mfa === 'admin_ops') return '<li><strong>Always for administrative operations:</strong> Force a secondary check for user creations, role alterations, and bulk data exports.</li>';
                            if (mfa === 'step_up') return '<li><strong>Step-Up Authentication:</strong> Trigger an active MFA prompt for high-sensitivity transactions, regardless of initial login status.</li>';
                            if (mfa === 'risk_based') return '<li><strong>Risk-Based:</strong> Trigger MFA when anomalous behavior (new country, new device, rapid calls) is identified.</li>';
                        }).join('')}
                    </ul>
                ` : ''}
            </section>

            <div class="doc-section-break"></div>

            <!-- ==========================================
                 SECTION 4: AUTHORIZATION
                 ========================================== -->
            <section id="doc-section-4">
                <h2><i class="fa-solid fa-unlock-keyhole"></i> 4. Authorization (AuthZ) Design</h2>
                <p>Authorization answers: <em>"Given who you are, what are you allowed to do?"</em>. We select the access control model strictly based on access control dimensions.</p>

                <div class="doc-callout tip" style="border-left-color: var(--accent-purple); background: rgba(142, 45, 226, 0.01);">
                    <h5 style="color: var(--accent-purple);"><i class="fa-solid fa-diagram-project"></i> Recommended Model: ${profile.authz.modelName}</h5>
                    <p>${profile.authz.desc}</p>
                    <p><strong>Core Integration Principles:</strong></p>
                    <ul style="margin-top: 0.5rem; margin-bottom: 0;">
                        ${profile.authz.principles.map(p => `<li>${p}</li>`).join('')}
                    </ul>
                </div>

                ${profile.authz.isMultiTenant ? `
                    <h3>4.2 Multi-Tenancy Boundary Rules</h3>
                    <div class="doc-callout danger">
                        <h5><i class="fa-solid fa-triangle-exclamation"></i> CRITICAL: Tenant Isolation Strategy</h5>
                        <p>To completely eliminate Broken Object Level Authorization (BOLA) and IDOR vulnerabilities:</p>
                        <ol style="margin-top: 0.5rem; margin-bottom: 0;">
                            <li><strong>Tenant ID must originate from the cryptographic verified token:</strong> Never trust <code>tenant_id</code> from headers, query strings, or POST request bodies.</li>
                            <li><strong>Tenant ID filter in every database fetch:</strong> Ensure queries follow this strict pattern: <code>SELECT * FROM resources WHERE id = :id AND tenant_id = :tenant_id</code>.</li>
                            <li><strong>Verify cross-tenant permissions:</strong> Write automated integration tests simulating Tenant A attempting to retrieve Tenant B resources. System MUST return a <strong>404 Not Found</strong> (never a 403, which leaks resource existence).</li>
                        </ol>
                    </div>
                ` : ''}

                ${profile.authz.hasAdminEndpoints ? `
                    <h3>4.3 Function-Level Access Protection</h3>
                    <ul>
                        <li><strong>Explicit checking:</strong> Middlewares must inspect roles/permissions before calling any logic. Public-by-default endpoints are prohibited.</li>
                        <li><strong>Route protection:</strong> Secure all paths matching <code>/api/admin/*</code> and <code>/api/internal/*</code>.</li>
                        <li><strong>HTTP Method boundary:</strong> Distinctly check permissions for <code>GET</code>, <code>POST</code>, and <code>DELETE</code>.</li>
                    </ul>
                ` : ''}

                <h3>4.4 Security Control Request Layering</h3>
                <p>Every single request entering the API boundary must pass through the four layers of control sequentially:</p>
                
                <div class="architecture-diagram-container">
                    ${svgDiagram}
                </div>
            </section>

            <div class="doc-section-break"></div>

            <!-- ==========================================
                 SECTION 5: CROSS-CUTTING
                 ========================================== -->
            <section id="doc-section-5">
                <h2><i class="fa-solid fa-arrows-spin"></i> 5. Cross-Cutting Security Concerns</h2>
                
                <h3>5.1 Token Strategy & Lifetimes</h3>
                <p>${profile.crossCutting.tokenStrategy}</p>
                
                <table style="width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9em; text-align: left;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--border-color); color: var(--accent-cyan);">
                            <th style="padding: 0.5rem;">Credential Type</th>
                            <th style="padding: 0.5rem;">Target Lifetime</th>
                            <th style="padding: 0.5rem;">Rotation Policy</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 0.5rem;">Access Tokens</td>
                            <td style="padding: 0.5rem;">${answers.access_lifetime || '15 Minutes'}</td>
                            <td style="padding: 0.5rem;">Ephemeral, no rotation. Recalled from memory or silently refreshed.</td>
                        </tr>
                        ${callers.includes('human_browser') || callers.includes('human_mobile') ? `
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 0.5rem;">Refresh Tokens</td>
                            <td style="padding: 0.5rem;">${answers.refresh_lifetime || '7 Days'}</td>
                            <td style="padding: 0.5rem;">Rotate on every single use. Invalidate older refresh token instantly.</td>
                        </tr>
                        ` : ''}
                        ${callers.includes('machine_thirdparty') ? `
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 0.5rem;">API Keys / Machine Secrets</td>
                            <td style="padding: 0.5rem;">No technical expiry</td>
                            <td style="padding: 0.5rem;">Rotate quarterly. Support zero-downtime double-key grace periods.</td>
                        </tr>
                        ` : ''}
                    </tbody>
                </table>

                <h3>5.2 Revocation Strategy</h3>
                <p>${profile.crossCutting.revocationStrategy}</p>

                <h3>5.3 Auditing & Logging Requirements</h3>
                ${hasAuditLogs ? `
                    <p>Implement real-time audit logging for the following events:</p>
                    <ul>
                        ${profile.crossCutting.auditLogging.map(log => {
                            if (log === 'log_failures') return '<li><strong>Authentication Failures:</strong> Log all 401 Unauthorized, 403 Forbidden, and BOLA 404 blocks.</li>';
                            if (log === 'log_mfa') return '<li><strong>Administrative Events:</strong> Log MFA challenges, credential changes, and permission alterations.</li>';
                            if (log === 'siem_feed') return '<li><strong>SIEM Integration:</strong> Stream UTC logs containing actor metadata, timestamps, client IPs, and trace IDs to central SIEM dashboards.</li>';
                        }).join('')}
                    </ul>
                ` : '<p>No audit log strategy specified. Minimal audit logs (logging standard error rates) recommended.</p>'}
            </section>

            <div class="doc-section-break"></div>

            <!-- ==========================================
                 SECTION 6: CODE SNIPPETS
                 ========================================== -->
            <section id="doc-section-6">
                <h2><i class="fa-solid fa-code"></i> 6. Technical Implementation Code Snippets</h2>
                <p>The following standardized code snippets demonstrate the implementation of key architectural layers defined above.</p>

                ${generateCodeSnippetsHTML(answers, profile)}
            </section>
        </div>
    `;

    return html;
}

// Generate the customized raw Markdown document
export function generateSecurityDocumentMarkdown(answers, profile) {
    const callers = answers.callers || [];
    const compliance = profile.crossCutting.complianceRequirements.toUpperCase();
    
    let md = `# Security Architecture Design Document

**System Threat Model & AuthN/Z Decision Specifications**
*Generated on: ${new Date().toLocaleDateString()} | System Risk Rating: ${profile.riskRating}*

---

## 1. Executive Summary & Threat Scorecard

The security controls detailed in this architecture design specify the authentication (AuthN) and authorization (AuthZ) mechanisms for this API, mapped directly to system threat vectors and operational constraints.

### 1.1 Scorecard Summary
* **Threat Complexity Score:** ${profile.riskScore} / 10
* **Risk Classification:** ${profile.riskRating}
* **Regulatory Compliance Target:** ${compliance}
* **Selected Caller Types:** ${callers.join(', ')}

---

## 2. System Threat Model

Below are primary attacker threat scenarios and targeted vectors mapped to system designs.

### 2.1 Caller Attack Vectors
${callers.map(c => {
    let desc = '';
    let threats = '';
    if (c === 'human_browser') {
        desc = 'Human via Browser (Web client)';
        threats = 'Session hijacking, XSS stealing tokens, CSRF attacks, credential stuffing.';
    } else if (c === 'human_mobile') {
        desc = 'Human via Native Mobile App';
        threats = 'Token theft from device, lack of PKCE resulting in authorization code interception, weak storage.';
    } else if (c === 'machine_internal') {
        desc = 'Machine-to-Machine Internal Service';
        threats = 'Leaked service credentials giving full service identity, broad downstream permissions.';
    } else if (c === 'machine_thirdparty') {
        desc = 'Machine-to-Machine Third-Party Integration';
        threats = 'Impersonation via leaked partner API key, client credential leak.';
    }
    return `* **${desc}**: Primary threats include: *${threats}*`;
}).join('\n')}

### 2.2 Attacker Goals & Targeted Mitigations
${profile.threats.length === 0 ? 'No advanced goals selected. Default mitigations apply.' : 
profile.threats.map(t => `
#### Threat: ${t.title}
* **Potential Impact:** ${t.impact}
* **Mandatory Controls:**
${t.mitigations.map(m => `  * ${m}`).join('\n')}
`).join('\n')}

---

## 3. Authentication (AuthN) Architecture

Authentication establishes identity. The design assigns distinct mechanisms per interface.

${Object.keys(profile.callers).map(key => {
    const c = profile.callers[key];
    return `
### Caller Interface: ${c.title}
* **Mechanism:** \`${c.mechanism}\`
* **Reasoning:** ${c.reasoning}
* **Implementation Strategy:** ${c.implementation}
`;
}).join('\n')}

${answers.human_mfa_requirement && answers.human_mfa_requirement.length > 0 ? `
### 3.2 Multi-Factor Authentication (MFA) Policy
MFA is contextualized as follows:
${answers.human_mfa_requirement.map(mfa => {
    if (mfa === 'admin_ops') return '* **Always for Admin Operations:** Forces MFA for creating/deleting users, changing permissions, configuration modifications.';
    if (mfa === 'step_up') return '* **Step-Up Authentication:** Challenge the user for high-value actions (transfers, deletions).';
    if (mfa === 'risk_based') return '* **Risk-Based:** Challenge user when login exhibits high risk metrics.';
}).join('\n')}
` : ''}

---

## 4. Authorization (AuthZ) Design

Authorization governs access boundaries.

### 4.1 Recommended Access Model: ${profile.authz.modelName}
${profile.authz.desc}

**Integration Principles:**
${profile.authz.principles.map(p => `* ${p}`).join('\n')}

${profile.authz.isMultiTenant ? `
### 4.2 Multi-Tenancy Boundary Isolation (CRITICAL BOLA prevention)
1. **Tenant ID must originate from the cryptographic verified token:** Never trust \`tenant_id\` from headers, query parameters, or POST request bodies.
2. **Tenant ID filter on database query:** Enforce strict query scopes: \`SELECT * FROM resources WHERE id = :id AND tenant_id = :tenant_id\`.
3. **Verify cross-tenant boundary explicitly:** In tests, verify that when Tenant A requests Tenant B data, the server returns a **404 Not Found** (never a 403).
` : ''}

### 4.3 Middlewares Layering Checklist
Requests must pass sequentially through four layers:
1. **Layer 1: AuthN Verification:** Is there a valid credential? (401 Unauthorized on failure)
2. **Layer 2: Coarse-Grained AuthZ:** Does role or token scope permit calling this route? (403 Forbidden on failure)
3. **Layer 3: Fine-Grained Object-Level AuthZ:** Does client own resource or belong to the tenant? (404 Not Found on failure)
4. **Layer 4: Business Logic AuthZ:** Is this operation permitted in current object state? (403 Forbidden with details on failure)

---

## 5. Cross-Cutting Concerns

### 5.1 Lifetimes Summary
* **Access Tokens:** ${answers.access_lifetime || '15 Minutes'} (Short lifetime limits window of compromise)
* **Refresh Tokens:** ${answers.refresh_lifetime || '7 Days'} (Must rotate refresh tokens on every single use)

### 5.2 Revocation Strategy
${profile.crossCutting.revocationStrategy}

### 5.3 Auditing
${profile.crossCutting.auditLogging && profile.crossCutting.auditLogging.length > 0 ? `
Implement UTC logging for:
${profile.crossCutting.auditLogging.map(log => {
    if (log === 'log_failures') return '* **AuthN/Z Failures:** Log 401, 403, and 404 events.';
    if (log === 'log_mfa') return '* **Security Alterations:** Log MFA events, password resets, key creations.';
    if (log === 'siem_feed') return '* **SIEM Feed:** Push formatted logs to SIEM for behavior analytics.';
}).join('\n')}
` : 'Standard application logging is recommended.'}

---

## 6. Technical Implementation Guidance

Review the interactive tool to fetch code snippets matching this layout.
`;
    return md;
}

// Generate the layered security Flowchart in SVG
function generateSVGDiagram(answers, profile) {
    const callers = answers.callers || [];
    
    // Choose AuthN middleware label
    let authnLabel = "Session Cookie / JWT Validator";
    if (callers.includes('human_browser') && answers.human_client_tech === 'server_rendered') {
        authnLabel = "Cookie Session AuthN";
    } else if (callers.includes('human_browser') && answers.human_client_tech === 'spa') {
        authnLabel = "SPA JWT Validator (Memory)";
    } else if (callers.includes('machine_internal') && answers.machine_security_bar === 'high_assurance') {
        authnLabel = "Gateway mTLS Validator";
    } else if (callers.includes('machine_thirdparty') && answers.thirdparty_bar === 'api_keys') {
        authnLabel = "API Key Validator (Header)";
    }

    // Choose AuthZ Model label
    const authzModel = profile.authz.modelName || "RBAC Layer";
    
    // Choose Object Check label
    const isMultiTenant = profile.authz.isMultiTenant;
    const objectLabel = isMultiTenant ? "Tenant ID Filter Check (404)" : "Resource Ownership Check";

    return `
    <svg width="680" height="340" viewBox="0 0 680 340">
        <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
            </marker>
            <marker id="arrow-cyan" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#00f2fe" />
            </marker>
        </defs>

        <!-- Dynamic Client Callers -->
        <rect x="20" y="30" width="120" height="280" class="svg-node highlight-purple" />
        <text x="80" y="55" class="svg-title">CLIENT SYSTEM</text>
        <line x1="20" y1="65" x2="140" y2="65" stroke="rgba(255,255,255,0.05)" stroke-width="1" />
        ${callers.map((c, i) => {
            let name = c.replace('human_', 'Human - ').replace('machine_', 'Machine - ');
            if (name.includes('browser')) name = "Browser App";
            if (name.includes('mobile')) name = "Mobile App";
            if (name.includes('internal')) name = "Internal Service";
            if (name.includes('thirdparty')) name = "Third-Party client";
            return `<text x="80" y="${95 + (i * 45)}" class="svg-text" fill="var(--accent-purple)">• ${name}</text>`;
        }).join('')}

        <!-- Arrows from Clients -->
        <path d="M 140 170 L 192 170" class="svg-arrow active" marker-end="url(#arrow-cyan)" />

        <!-- Layer 1: AuthN Validation -->
        <rect x="200" y="130" width="130" height="80" class="svg-node active" />
        <text x="265" y="165" class="svg-title">LAYER 1: AuthN</text>
        <text x="265" y="185" class="svg-text" fill="var(--text-muted)">${authnLabel}</text>

        <!-- Arrow to Layer 2 -->
        <path d="M 330 170 L 352 170" class="svg-arrow active" marker-end="url(#arrow-cyan)" />

        <!-- Layer 2: Coarse AuthZ -->
        <rect x="360" y="130" width="130" height="80" class="svg-node active" />
        <text x="425" y="165" class="svg-title">LAYER 2: Coarse AuthZ</text>
        <text x="425" y="185" class="svg-text" fill="var(--text-muted)">${authzModel}</text>

        <!-- Arrow to Layer 3 -->
        <path d="M 490 170 L 512 170" class="svg-arrow active" marker-end="url(#arrow-cyan)" />

        <!-- Layer 3: Fine-grained Object AuthZ -->
        <rect x="520" y="130" width="140" height="80" class="svg-node active" />
        <text x="590" y="165" class="svg-title">LAYER 3: Fine AuthZ</text>
        <text x="590" y="185" class="svg-text" fill="var(--text-muted)">${objectLabel}</text>

        <!-- Downward/Right arrow to DB boundary -->
        <path d="M 590 210 L 590 270 L 460 270" fill="none" stroke="var(--accent-cyan)" stroke-width="1.5" marker-end="url(#arrow-cyan)" />

        <!-- Database query filter -->
        <rect x="300" y="240" width="150" height="60" class="svg-node" />
        <text x="375" y="265" class="svg-title" fill="var(--state-success)">DATABASE LAYER</text>
        <text x="375" y="285" class="svg-text" fill="var(--text-muted)">WHERE tenant_id = :token_tenant</text>
    </svg>
    `;
}

// Generate the customized code snippets block
function generateCodeSnippetsHTML(answers, profile) {
    const callers = answers.callers || [];
    const isMultiTenant = profile.authz.isMultiTenant;
    
    let snippets = '';

    // 1. Layering Middleware Stack (NodeJS/Express Example)
    snippets += `
        <div class="code-container">
            <div class="code-header">
                <span class="code-title">middleware/layer_security.js (Node.js/Express)</span>
                <button class="code-copy-btn" onclick="navigator.clipboard.writeText(this.closest('.code-container').querySelector('code').innerText); this.innerHTML='<i class=\\'fa-solid fa-check\\'></i> Copied!'; setTimeout(()=>this.innerHTML='Copy', 1500)">Copy</button>
            </div>
            <pre><code>// 1. Layer 1: Authentication Middleware
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing credential (AuthN failure)' });
    
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // Injects { userId, tenantId, role, scopes }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token (AuthN failure)' });
  }
};

// 2. Layer 2: Coarse-Grained Authorization (Role check)
const authorizeRole = (requiredRoles) => {
  return (req, res, next) => {
    if (!req.user || !requiredRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient privileges (Coarse AuthZ failure)' });
    }
    next();
  };
};

// 3. Layer 3: Fine-Grained Object/Tenant Isolation (BOLA mitigation)
const authorizeTenant = async (req, res, next) => {
  const resourceId = req.params.id;
  const userTenantId = req.user.tenantId; // Derived from verified token claim
  
  const resource = await db.fetchResourceById(resourceId);
  
  // Strict tenant boundary test
  if (!resource || resource.tenantId !== userTenantId) {
    // Return 404 NOT FOUND to avoid revealing resource existence to attackers
    return res.status(404).json({ error: 'Resource not found' });
  }
  
  req.resource = resource;
  next();
};

// Application Route leveraging full layering stack
app.delete('/api/findings/:id', 
  authenticateUser, 
  authorizeRole(['senior_analyst', 'admin']), 
  authorizeTenant, 
  async (req, res) => {
    await db.deleteFinding(req.resource.id);
    res.json({ message: 'Resource successfully deleted' });
});</code></pre>
        </div>
    `;

    // 2. Dynamic Caller-Specific Authentication Snippets
    if (callers.includes('human_browser')) {
        const clientTech = answers.human_client_tech || 'spa';
        if (clientTech === 'server_rendered') {
            snippets += `
                <div class="code-container">
                    <div class="code-header">
                        <span class="code-title">server.js (Stateful Express Session Cookie Config)</span>
                        <button class="code-copy-btn" onclick="navigator.clipboard.writeText(this.closest('.code-container').querySelector('code').innerText); this.innerHTML='<i class=\\'fa-solid fa-check\\'></i> Copied!'; setTimeout(()=>this.innerHTML='Copy', 1500)">Copy</button>
                    </div>
                    <pre><code>const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redisClient = require('./redis-client');

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  name: 'secure_session_id', // Opaque, non-identifiable name
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,  // Prevents XSS token exfiltration
    secure: true,    // Enforce HTTPS
    sameSite: 'lax', // CSRF mitigation
    maxAge: 30 * 60 * 1000 // 30 Minute idle timeout
  }
}));</code></pre>
                </div>
            `;
        } else {
            snippets += `
                <div class="code-container">
                    <div class="code-header">
                        <span class="code-title">auth_controller.js (SPA In-Memory Access + HttpOnly Refresh Cookie)</span>
                        <button class="code-copy-btn" onclick="navigator.clipboard.writeText(this.closest('.code-container').querySelector('code').innerText); this.innerHTML='<i class=\\'fa-solid fa-check\\'></i> Copied!'; setTimeout(()=>this.innerHTML='Copy', 1500)">Copy</button>
                    </div>
                    <pre><code>// Auth Controller: Login Endpoint returning memory access token + cookie refresh token
exports.login = async (req, res) => {
  const { username, password } = req.body;
  const user = await db.verifyUser(username, password);
  
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  
  const accessToken = generateAccessToken(user); // Expires in 15 mins
  const refreshToken = generateRefreshToken(user); // Expires in 7 days
  
  // Refresh token is bound strictly to an HttpOnly secure cookie
  res.cookie('secure_refresh_token', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/api/auth/refresh', // Restricted scope path
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
  
  // Return the access token to be saved in client JavaScript Memory state
  res.json({ access_token: accessToken, expires_in: 900 });
};</code></pre>
                </div>
            `;
        }
    }

    if (callers.includes('machine_thirdparty') && answers.thirdparty_bar === 'api_keys') {
        snippets += `
            <div class="code-container">
                <div class="code-header">
                    <span class="code-title">middleware/api_key_validator.js (Opaque Custom Header Verification)</span>
                    <button class="code-copy-btn" onclick="navigator.clipboard.writeText(this.closest('.code-container').querySelector('code').innerText); this.innerHTML='<i class=\\'fa-solid fa-check\\'></i> Copied!'; setTimeout(()=>this.innerHTML='Copy', 1500)">Copy</button>
                </div>
                <pre><code>const crypto = require('crypto');

const validateAPIKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key']; // Always use headers, NEVER URL parameters
  if (!apiKey) return res.status(401).json({ error: 'Missing API Key' });
  
  // Safe validation check: verify standard system prefix
  if (!apiKey.startsWith('sk_live_')) {
    return res.status(401).json({ error: 'Malformed API Key structure' });
  }

  // Hash the incoming key to compare with the registry database
  const hashedIncoming = crypto.createHash('sha256').update(apiKey).digest('hex');
  const partnerRegistry = await db.findKeyByHash(hashedIncoming);
  
  if (!partnerRegistry) {
    return res.status(401).json({ error: 'Invalid API Key' });
  }
  
  req.partner = partnerRegistry; // { partnerId, scopes }
  next();
};</code></pre>
            </div>
        `;
    }

    // 3. Multi-Tenancy Database Scope
    if (isMultiTenant) {
        snippets += `
            <div class="code-container">
                <div class="code-header">
                    <span class="code-title">repositories/finding_repository.js (Strict Database Tenant Scoping)</span>
                    <button class="code-copy-btn" onclick="navigator.clipboard.writeText(this.closest('.code-container').querySelector('code').innerText); this.innerHTML='<i class=\\'fa-solid fa-check\\'></i> Copied!'; setTimeout(()=>this.innerHTML='Copy', 1500)">Copy</button>
                </div>
                <pre><code>// Example SQL database retrieval scoping tenant isolation
const fetchAllFindingsForTenant = async (tenantId) => {
  const query = 'SELECT id, title, severity, created_at FROM findings WHERE tenant_id = ?';
  const [rows] = await dbPool.execute(query, [tenantId]); // Strictly parameterized, no manual concatenation
  return rows;
};

// Example Node ORM (Prisma) scoped retrieval
const fetchFindingPrisma = async (id, tenantId) => {
  return await prisma.finding.findFirst({
    where: {
      id: id,
      tenantId: tenantId // Tenant check is non-negotiable on every single lookup
    }
  });
};</code></pre>
            </div>
        `;
    }

    return snippets;
}
