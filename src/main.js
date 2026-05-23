// Main orchestrator for the Threat Modelling and Auth Decision Wizard.
import { questions, authnHumanQuestions, authnMachineQuestions, authnThirdPartyMachineQuestions, authzQuestions, crossCuttingQuestions, phases } from './questions.js';
import { evaluateSecurityProfile } from './decision-engine.js';
import { generateSecurityDocumentHTML, generateSecurityDocumentMarkdown } from './document-generator.js';

// Application State
let answers = {
    callers: [],
    attacker_goals: [],
    authz_dimensions: [],
    audit_logging: [],
    human_mfa_requirement: [],
    // Set default values for multi-questions
    can_hold_secret: 'yes',
    browser_available: 'yes',
    verifiers_count: 'one',
    regulatory_context: 'none',
    immediate_revocation: 'no',
    access_lifetime: '15m',
    refresh_lifetime: '7d'
};

let currentStepIndex = 0;
let wizardSteps = [];

// DOM Elements
const wizardSlideContainer = document.getElementById('wizard-slide');
const btnBack = document.getElementById('btn-back');
const btnNext = document.getElementById('btn-next');
const slideIndicators = document.getElementById('slide-indicators');
const currentPhaseNameEl = document.getElementById('current-phase-name');
const progressBarFill = document.getElementById('progress-bar-fill');
const progressPercentageEl = document.getElementById('progress-percentage');

// Sidebar DOM Elements
const sidebarCallersList = document.getElementById('sidebar-callers-list');
const sidebarThreatsList = document.getElementById('sidebar-threats-list');
const sidebarComplianceList = document.getElementById('sidebar-compliance-list');
const riskScoreRadial = document.getElementById('risk-score-radial');
const riskScoreNum = document.getElementById('risk-score-num');
const riskRatingLabel = document.getElementById('risk-rating-label');

// Document Overlay DOM Elements
const documentOverlay = document.getElementById('document-overlay');
const docContentViewer = document.getElementById('doc-content-viewer');
const btnCloseDoc = document.getElementById('btn-close-doc');
const btnCopyMd = document.getElementById('btn-copy-md');
const btnDownloadMd = document.getElementById('btn-download-md');
const btnPrintDoc = document.getElementById('btn-print-doc');
const btnResetWizard = document.getElementById('btn-reset-wizard');
const docToc = document.getElementById('doc-toc');

// Initialize App
function init() {
    updateWizardSteps();
    renderSlide();
    updateSidebar();
    
    // Register global event listeners
    btnNext.addEventListener('click', handleNext);
    btnBack.addEventListener('click', handleBack);
    btnCloseDoc.addEventListener('click', closeDocument);
    btnCopyMd.addEventListener('click', copyMarkdownToClipboard);
    btnDownloadMd.addEventListener('click', downloadMarkdownFile);
    btnPrintDoc.addEventListener('click', () => window.print());
    btnResetWizard.addEventListener('click', () => {
        if (confirm('Are you sure you want to reset the wizard? All selections will be cleared.')) {
            resetWizard();
        }
    });
    
    // Manage document TOC scrolling highlight
    setupTocScrollSpy();
}

function resetWizard() {
    // Reset state to initial values
    answers = {
        callers: [],
        attacker_goals: [],
        authz_dimensions: [],
        audit_logging: [],
        human_mfa_requirement: [],
        can_hold_secret: 'yes',
        browser_available: 'yes',
        verifiers_count: 'one',
        regulatory_context: 'none',
        immediate_revocation: 'no',
        access_lifetime: '15m',
        refresh_lifetime: '7d'
    };
    currentStepIndex = 0;
    updateWizardSteps();
    renderSlide();
    updateSidebar();
    closeDocument();
}

// Compute the list of wizard steps dynamically based on current answers
function updateWizardSteps() {
    const steps = [];
    
    // Phase 1: Threat Modelling (All base questions)
    steps.push(questions.find(q => q.id === 'callers'));
    steps.push(questions.find(q => q.id === 'protection_level'));
    steps.push(questions.find(q => q.id === 'attacker_goals'));
    steps.push(questions.find(q => q.id === 'operational_env'));
    
    // Phase 2: AuthN (Dynamic branches based on caller types)
    const callers = answers.callers || [];
    
    if (callers.includes('human_browser') || callers.includes('human_mobile')) {
        steps.push(authnHumanQuestions.find(q => q.id === 'human_first_party'));
        
        // Only ask about tech (server vs spa) if browser is a caller and it's a first party
        if (answers.human_first_party === 'first_party' && callers.includes('human_browser')) {
            steps.push(authnHumanQuestions.find(q => q.id === 'human_client_tech'));
        }
        
        steps.push(authnHumanQuestions.find(q => q.id === 'human_mfa_requirement'));
    }
    
    if (callers.includes('machine_internal')) {
        steps.push(authnMachineQuestions.find(q => q.id === 'machine_context'));
        
        // Security bar is only for pure service identities (no user ctx)
        if (answers.machine_context === 'service_identity') {
            steps.push(authnMachineQuestions.find(q => q.id === 'machine_security_bar'));
        }
    }
    
    if (callers.includes('machine_thirdparty')) {
        steps.push(authnThirdPartyMachineQuestions.find(q => q.id === 'thirdparty_bar'));
    }
    
    // Phase 3: Authorization (AuthZ)
    steps.push(authzQuestions.find(q => q.id === 'authz_dimensions'));
    steps.push(authzQuestions.find(q => q.id === 'is_multitenant'));
    steps.push(authzQuestions.find(q => q.id === 'function_protection'));
    
    // Phase 4: Cross-Cutting concerns
    steps.push(crossCuttingQuestions.find(q => q.id === 'token_lifetime_input'));
    steps.push(crossCuttingQuestions.find(q => q.id === 'audit_logging'));
    
    wizardSteps = steps;
}

// Render the active question slide
function renderSlide() {
    const q = wizardSteps[currentStepIndex];
    if (!q) return;

    // Determine current phase details
    const activePhase = phases.find(p => p.id === q.phase) || phases[0];
    currentPhaseNameEl.textContent = activePhase.name;
    
    // Update progress bar
    const progressPercent = Math.round(((currentStepIndex) / (wizardSteps.length)) * 100);
    progressBarFill.style.width = `${progressPercent}%`;
    progressPercentageEl.textContent = `${progressPercent}%`;

    // Render indicators/bullets
    renderIndicators();

    // Render Slide HTML
    let html = `
        <div class="slide-title-wrapper">
            <span class="phase-indicator">${activePhase.name}</span>
            <h2>${q.title}</h2>
            <p class="slide-subtitle">${q.subtitle}</p>
        </div>
    `;

    // Render Choice Grid
    if (q.type === 'checkbox' || q.type === 'radio') {
        html += `<div class="options-grid">`;
        q.options.forEach(opt => {
            const isSelected = isOptionSelected(q.id, opt.value);
            const isPurple = q.phase === 'authz' || opt.value === 'high_assurance' || opt.value === 'very_high' || opt.value === 'mtls_partner';
            
            html += `
                <div class="option-card ${isSelected ? 'selected' : ''} ${isPurple ? 'purple-theme' : ''}" data-qid="${q.id}" data-val="${opt.value}">
                    <div class="${q.type === 'checkbox' ? 'option-checkbox-indicator' : 'option-radio-indicator'}">
                        ${q.type === 'checkbox' ? '<i class="fa-solid fa-check"></i>' : ''}
                    </div>
                    <div class="option-icon">
                        <i class="fa-solid ${opt.icon}"></i>
                    </div>
                    <div class="option-details">
                        <h4>${opt.label}</h4>
                        <p>${opt.desc || opt.example}</p>
                        
                        ${opt.threat ? `
                            <div class="option-threat-box">
                                <i class="fa-solid fa-triangle-exclamation threat-icon"></i>
                                <span>Threats: ${opt.threat}</span>
                            </div>
                        ` : ''}
                        
                        ${opt.mitigation ? `
                            <div class="option-threat-box" style="background: rgba(16,185,129,0.05); border-color: rgba(16,185,129,0.15); color: #a7f3d0;">
                                <i class="fa-solid fa-shield threat-icon" style="color: var(--state-success);"></i>
                                <span>Mitigation: ${opt.mitigation}</span>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        });
        html += `</div>`;
    } 
    // Render Select lists (Multi Question layouts)
    else if (q.type === 'multi_question') {
        html += `<div style="display: flex; flex-direction: column; gap: 1.2rem;">`;
        q.questions.forEach(subQ => {
            const currentVal = answers[subQ.id] || '';
            
            html += `
                <div class="text-input-group">
                    <label for="${subQ.id}">${subQ.label}</label>
                    <select id="${subQ.id}" class="cyber-select" data-subqid="${subQ.id}">
                        ${subQ.options.map(o => `<option value="${o.value}" ${o.value === currentVal ? 'selected' : ''}>${o.label}</option>`).join('')}
                    </select>
                </div>
            `;
        });
        html += `</div>`;
    }

    // Set layout content
    wizardSlideContainer.innerHTML = html;

    // Attach interaction event listeners to new cards
    const cards = wizardSlideContainer.querySelectorAll('.option-card');
    cards.forEach(card => {
        card.addEventListener('click', handleOptionSelect);
    });

    // Attach select element event listeners
    const selects = wizardSlideContainer.querySelectorAll('.cyber-select');
    selects.forEach(sel => {
        sel.addEventListener('change', handleSelectChange);
    });

    // Update navigation button status
    btnBack.disabled = (currentStepIndex === 0);
    
    if (currentStepIndex === wizardSteps.length - 1) {
        btnNext.innerHTML = `Generate Strategy <i class="fa-solid fa-file-shield"></i>`;
        btnNext.className = "btn btn-primary purple";
    } else {
        btnNext.innerHTML = `Continue <i class="fa-solid fa-arrow-right"></i>`;
        btnNext.className = "btn btn-primary";
    }
}

// Render the slide indicators (bullets at the bottom)
function renderIndicators() {
    let html = '';
    wizardSteps.forEach((step, idx) => {
        let stateClass = '';
        if (idx === currentStepIndex) {
            stateClass = 'active';
        } else if (idx < currentStepIndex) {
            stateClass = 'completed';
        }
        html += `<div class="bullet ${stateClass}"></div>`;
    });
    slideIndicators.innerHTML = html;
}

// Handle checkbox/radio clicks
function handleOptionSelect(e) {
    const card = e.currentTarget;
    const qid = card.dataset.qid;
    const val = card.dataset.val;
    const q = wizardSteps[currentStepIndex];

    if (q.type === 'checkbox') {
        if (!Array.isArray(answers[qid])) {
            answers[qid] = [];
        }
        const index = answers[qid].indexOf(val);
        if (index > -1) {
            answers[qid].splice(index, 1);
            card.classList.remove('selected');
        } else {
            answers[qid].push(val);
            card.classList.add('selected');
        }
    } else {
        // Radio logic
        answers[qid] = val;
        wizardSlideContainer.querySelectorAll('.option-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
    }

    // Update state & side indicators
    updateWizardSteps();
    updateSidebar();
}

// Handle select tags
function handleSelectChange(e) {
    const select = e.target;
    const subQid = select.dataset.subqid;
    answers[subQid] = select.value;
    
    updateWizardSteps();
    updateSidebar();
}

// Check helper
function isOptionSelected(qid, value) {
    const ans = answers[qid];
    if (Array.isArray(ans)) {
        return ans.includes(value);
    }
    return ans === value;
}

// Navigation flow: NEXT
function handleNext() {
    const q = wizardSteps[currentStepIndex];
    
    // Trigger validation logic if configured
    if (q.validate) {
        const error = q.validate(answers);
        if (error) {
            alert(error);
            return;
        }
    }

    if (currentStepIndex === wizardSteps.length - 1) {
        generateAndShowDocument();
    } else {
        currentStepIndex++;
        renderSlide();
    }
}

// Navigation flow: BACK
function handleBack() {
    if (currentStepIndex > 0) {
        currentStepIndex--;
        renderSlide();
    }
}

// Evaluate inputs and compile recommendations
function updateSidebar() {
    const profile = evaluateSecurityProfile(answers);

    // 1. Update Scorecard gauge
    const score = profile.riskScore;
    const rating = profile.riskRating;
    
    riskScoreNum.textContent = `${score} / 10`;
    riskRatingLabel.textContent = rating;

    // Color gradient shifts based on score severity
    let color = 'var(--accent-cyan)';
    if (score > 3 && score <= 5.5) {
        color = 'var(--accent-blue)';
        riskRatingLabel.style.color = 'var(--accent-blue)';
    } else if (score > 5.5 && score <= 8) {
        color = 'var(--state-warning)';
        riskRatingLabel.style.color = 'var(--state-warning)';
    } else if (score > 8) {
        color = 'var(--state-danger)';
        riskRatingLabel.style.color = 'var(--state-danger)';
    } else {
        riskRatingLabel.style.color = 'var(--accent-cyan)';
    }

    riskScoreRadial.style.stroke = color;
    
    // Circular stroke offset calculation
    const circumference = 251.2;
    const offset = circumference - (score / 10) * circumference;
    riskScoreRadial.style.strokeDashoffset = offset;

    // 2. Render Callers List
    if (answers.callers && answers.callers.length > 0) {
        sidebarCallersList.innerHTML = answers.callers.map(c => {
            let label = 'Human';
            let icon = 'fa-user';
            if (c === 'human_browser') { label = 'Human Browser'; icon = 'fa-desktop'; }
            if (c === 'human_mobile') { label = 'Human Mobile'; icon = 'fa-mobile-screen-button'; }
            if (c === 'machine_internal') { label = 'Internal Service'; icon = 'fa-server'; }
            if (c === 'machine_thirdparty') { label = 'Third-Party Machine'; icon = 'fa-hands-holding-child'; }
            return `<li><i class="fa-solid ${icon} caller-icon"></i> ${label}</li>`;
        }).join('');
    } else {
        sidebarCallersList.innerHTML = '<li class="empty-list-placeholder">None specified yet</li>';
    }

    // 3. Render threats list
    if (answers.attacker_goals && answers.attacker_goals.length > 0) {
        sidebarThreatsList.innerHTML = answers.attacker_goals.map(g => {
            let label = 'Threat';
            if (g === 'impersonate_user') label = 'User Impersonation';
            if (g === 'impersonate_app') label = 'Client Secret Theft';
            if (g === 'escalate_privilege') label = 'Privilege Escalation';
            if (g === 'abuse_scale') label = 'Scraping / Abuse';
            if (g === 'persist_rotation') label = 'Credential Persistence';
            if (g === 'pivot_system') label = 'Downstream Pivot';
            return `<li><i class="fa-solid fa-bug"></i> ${label}</li>`;
        }).join('');
    } else {
        sidebarThreatsList.innerHTML = '<li class="empty-list-placeholder">Identify attacker goals to map threats</li>';
    }

    // 4. Render compliance tag
    const reg = answers.regulatory_context || 'none';
    if (reg !== 'none') {
        sidebarComplianceList.innerHTML = `<span class="compliance-tag">${reg.toUpperCase()} COMPLIANT</span>`;
    } else {
        sidebarComplianceList.innerHTML = '<span class="compliance-tag empty">No constraints</span>';
    }
}

// Compile the document and show the preview modal
function generateAndShowDocument() {
    const profile = evaluateSecurityProfile(answers);
    const htmlContent = generateSecurityDocumentHTML(answers, profile);
    
    docContentViewer.innerHTML = htmlContent;
    documentOverlay.classList.remove('hidden');
    document.body.style.overflow = 'hidden'; // Lock background scrolling
}

// Close preview document
function closeDocument() {
    documentOverlay.classList.add('hidden');
    document.body.style.overflow = '';
}

// Clipboard export helper
function copyMarkdownToClipboard() {
    const profile = evaluateSecurityProfile(answers);
    const md = generateSecurityDocumentMarkdown(answers, profile);
    
    navigator.clipboard.writeText(md).then(() => {
        btnCopyMd.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
        setTimeout(() => {
            btnCopyMd.innerHTML = `<i class="fa-solid fa-copy"></i> Copy Markdown`;
        }, 2000);
    }).catch(err => {
        alert('Could not copy markdown to clipboard: ' + err);
    });
}

// File export helper
function downloadMarkdownFile() {
    const profile = evaluateSecurityProfile(answers);
    const md = generateSecurityDocumentMarkdown(answers, profile);
    
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'security_architecture_design.md');
    document.body.appendChild(link);
    link.click();
    
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Manage dynamic TOC link highlighting when scrolling the document body
function setupTocScrollSpy() {
    docContentViewer.addEventListener('scroll', () => {
        const sections = docContentViewer.querySelectorAll('section');
        const tocLinks = docToc.querySelectorAll('a');
        
        let currentSectionId = '';
        sections.forEach(sec => {
            const rect = sec.getBoundingClientRect();
            // If the top of the section is in the top-half of the viewer container
            if (rect.top <= 200 && rect.bottom >= 100) {
                currentSectionId = sec.id;
            }
        });
        
        if (currentSectionId) {
            tocLinks.forEach(link => {
                if (link.getAttribute('href') === `#${currentSectionId}`) {
                    link.classList.add('active');
                } else {
                    link.classList.remove('active');
                }
            });
        }
    });

    // Make TOC link clicks smooth-scroll the viewer
    const tocLinks = docToc.querySelectorAll('a');
    tocLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href');
            const targetSection = docContentViewer.querySelector(targetId);
            
            if (targetSection) {
                targetSection.scrollIntoView({ behavior: 'smooth' });
                tocLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            }
        });
    });
}

// Run app init
init();
