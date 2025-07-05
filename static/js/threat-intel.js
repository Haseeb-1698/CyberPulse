// Global variable to store the fetched and merged threat intelligence data
let allThreatIntelData = [];
let uniqueThreatIntelData = []; // For deduplicated data

// Function to fetch, merge, and load threat intelligence data
async function loadThreatIntelligence() {
    const VULN_DATA_URL = '/static/data/vulnerabilities_data.json';
    // Remediation data is assumed to be available as a global variable 'remediationData'
    // loaded from static/data/structured_remediation_enhanced.js

    showLoadingMessageThreatIntel(true);

    try {
        const response = await fetch(VULN_DATA_URL);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status} for ${VULN_DATA_URL}`);
        }
        const vulnerabilitiesData = await response.json();

        // Access the global remediationData variable
        const globalRemData = typeof remediationData !== 'undefined' ? remediationData : null;

        if (globalRemData === null) {
            console.warn("Threat Intel: Structured remediation data (global variable 'remediationData') is not available. Details might be incomplete.");
        }

        // Merge data
        allThreatIntelData = vulnerabilitiesData.map(vuln => {
            const baseVuln = (typeof vuln === 'object' && vuln !== null) ? vuln : { cve_id: 'unknown' };
            let mergedVuln = { ...baseVuln };
            // Remediation data is an object keyed by CVE_ID
            const enhancedRemediation = (globalRemData && typeof globalRemData === 'object' && globalRemData[baseVuln.cve_id]) 
                ? globalRemData[baseVuln.cve_id] 
                : null;

            if (enhancedRemediation) {
                mergedVuln = {
                    ...baseVuln,
                    // Prioritize fields from structured_remediation_enhanced.js
                    title: enhancedRemediation.title || baseVuln.title,
                    summary: enhancedRemediation.summary || baseVuln.summary,
                    description: enhancedRemediation.description || baseVuln.description,
                    // Use severity from baseVuln (vulnerabilities_data.json) primarily, 
                    // as structured_remediation might have a different perspective or fixed value.
                    // If you want remediation to override, switch the order or use enhancedRemediation.severity directly.
                    severity: baseVuln.severity || enhancedRemediation.severity || 'Unknown',
                    cvss_score: enhancedRemediation.cvss_score || baseVuln.cvss_score,
                    cwe: enhancedRemediation.cwe || baseVuln.cwe,
                    remediation_steps: enhancedRemediation.remediation_steps || (baseVuln.ai_remediation ? baseVuln.ai_remediation.remediation_steps : []),
                    impact: enhancedRemediation.impact || baseVuln.impact,
                    priority: enhancedRemediation.priority || baseVuln.priority, 
                    references: enhancedRemediation.references || baseVuln.references,
                    mitre_techniques: enhancedRemediation.mitre_techniques || (baseVuln.mitre_data ? baseVuln.mitre_data.techniques : []),
                    threat_actors: enhancedRemediation.threat_actors || (baseVuln.mitre_data ? baseVuln.mitre_data.actors : []),
                    exploit_info: enhancedRemediation.exploit_info || baseVuln.exploit_info,
                    // Ensure ai_remediation is taken from the correct source or merged if necessary
                    ai_remediation: enhancedRemediation.ai_remediation || baseVuln.ai_remediation 
                };
            }
            // Fallback severity if not set by either source during merge
            mergedVuln.severity = mergedVuln.severity || mergedVuln.predicted_severity || 'Unknown';
            return mergedVuln;
        });

        // Deduplicate based on CVE ID (normalized to uppercase)
        const seenCVEs = new Map();
        uniqueThreatIntelData = [];
        allThreatIntelData.forEach(vuln => {
            if (vuln && vuln.cve_id && typeof vuln.cve_id === 'string') { // Ensure vuln, cve_id exist and cve_id is a string
                const normalizedCVE = vuln.cve_id.toUpperCase();
                if (!seenCVEs.has(normalizedCVE)) {
                    seenCVEs.set(normalizedCVE, true);
                    uniqueThreatIntelData.push(vuln);
                }
            }
            // Items without a valid string cve_id will be excluded from uniqueThreatIntelData
        });
        console.log(`Threat Intel: Loaded ${allThreatIntelData.length} total, ${uniqueThreatIntelData.length} unique vulnerabilities.`);

        displayThreatIntelligence(uniqueThreatIntelData);

    } catch (error) {
        console.error('Failed to load threat intelligence data:', error);
        const container = document.getElementById('threat-intel-container');
        if (container) {
            container.innerHTML = `<p class="error-message">Failed to load threat intelligence. ${error.message}</p>`;
        }
    } finally {
        showLoadingMessageThreatIntel(false);
    }
}

function displayThreatIntelligence(dataToDisplay) {
    const container = document.getElementById('threat-intel-container');
    const filterControls = document.getElementById('threat-intel-filters'); // Assuming filters are separate

    if (!container) {
        console.error("Threat intelligence container not found.");
        return;
    }
    
    container.innerHTML = ''; // Clear previous cards

    if (!dataToDisplay || dataToDisplay.length === 0) {
        container.innerHTML = '<p>No threat intelligence data available.</p>';
        if(filterControls) filterControls.style.display = 'none';
        return;
    }
    if(filterControls) filterControls.style.display = 'flex'; // Show filters if data exists

    const severities = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
    severities.forEach(sev => {
        const vulnsOfSeverity = dataToDisplay.filter(vuln => (vuln.severity || 'Unknown').toLowerCase() === sev.toLowerCase());
        if (vulnsOfSeverity.length > 0) {
            const section = document.createElement('div');
            section.className = `threat-section ${sev.toLowerCase()}-section`; // Added -section for clarity
            section.setAttribute('data-severity', sev.toLowerCase());
            
            const title = document.createElement('h3');
            title.className = 'section-title';
            title.textContent = `${sev} Severity Vulnerabilities (${vulnsOfSeverity.length})`;
            section.appendChild(title);

            const grid = document.createElement('div');
            grid.className = 'threat-intel-grid';
            vulnsOfSeverity.forEach(vuln => {
                grid.appendChild(createThreatCard(vuln));
            });
            section.appendChild(grid);
            container.appendChild(section);
        }
    });
}

// Function to create a single threat intelligence card
function createThreatCard(vuln) {
    const card = document.createElement('div');
    card.className = 'threat-card';
    // Add severity specific class for styling if needed
    card.classList.add((vuln.severity || 'unknown').toLowerCase() + '-card-ti'); 

    const bestScore = getBestScoreThreatIntel(vuln);
    const severity = vuln.severity || 'Unknown';

    card.innerHTML = `
        <div class="threat-header">
            <h3>${vuln.cve_id || 'N/A'}</h3>
            <span class="severity-badge ${severity.toLowerCase()}">${severity}</span>
        </div>
        <p class="threat-title">${vuln.title || truncateText(vuln.summary, 80) || truncateText(vuln.description, 80) || 'No title available'}</p>
        <div class="detail-row">
            <span class="label">CVSS/Best Score:</span>
            <span>${bestScore}</span>
        </div>
        ${vuln.exploit_info && vuln.exploit_info.count > 0 ? 
            `<div class="detail-row exploit-indicator">
                <span class="label"><i class="fas fa-bomb"></i> Exploits:</span>
                <span>${vuln.exploit_info.count} (Maturity: ${vuln.exploit_info.maturity || 'N/A'})</span>
            </div>` : ''
        }
        <div class="card-actions-ti">
             <button class="btn btn-sm btn-details-ti">View Details</button>
        </div>
    `;

    card.querySelector('.btn-details-ti').addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent card click if button has its own handler
        showThreatIntelDetailsModal(vuln); 
    });
    
    // Make entire card clickable as well if button isn't specifically clicked
    card.addEventListener('click', () => {
        showThreatIntelDetailsModal(vuln);
    });

    return card;
}

// Function to show detailed threat intelligence in a modal
function showThreatIntelDetailsModal(vuln) {
    const modal = document.getElementById('threatIntelModal'); // Assuming this modal exists in your HTML
    if (!modal) {
        console.error("Threat intelligence modal (threatIntelModal) not found.");
        alert("Modal not found. Cannot display details.");
        return;
    }

    document.getElementById('modalCveId').textContent = vuln.cve_id || 'N/A';
    const modalContent = document.getElementById('modal-ti-content');
    if (!modalContent) {
        console.error("Modal content area (modal-ti-content) not found.");
        return;
    }

    let mitreHtml = 'N/A';
    if (vuln.mitre_techniques && vuln.mitre_techniques.length > 0) {
        mitreHtml = '<ul>' + vuln.mitre_techniques.map(tech => `<li>${tech.id || ''}: ${tech.name || 'N/A'} (Relevance: ${tech.relevance || 'N/A'})</li>`).join('') + '</ul>';
    }

    let actorsHtml = (vuln.threat_actors && vuln.threat_actors.length > 0) ? vuln.threat_actors.join(', ') : 'N/A';

    let exploitLinksHtml = 'N/A';
    if (vuln.exploit_info && vuln.exploit_info.links && vuln.exploit_info.links.length > 0) {
        exploitLinksHtml = '<ul>' + vuln.exploit_info.links.map(link => `<li><a href="${link}" target="_blank">${link}</a></li>`).join('') + '</ul>';
    }
    
    let referencesHtml = 'N/A';
    if (vuln.references && typeof vuln.references === 'object') {
        const allRefs = [
            ...(vuln.references.vendor_advisories || []),
            ...(vuln.references.technical_reports || []),
            ...(vuln.references.mitre_links || []),
            ...(vuln.references.exploit_links || []), // Include exploit links from references if structured differently
            ...(vuln.references.other || [])
        ].filter(ref => ref); // Filter out null/undefined refs
        if (allRefs.length > 0) {
             referencesHtml = '<ul>' + allRefs.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('') + '</ul>';
        }
    } else if (Array.isArray(vuln.references) && vuln.references.length > 0) { // Fallback if references is a simple array
        referencesHtml = '<ul>' + vuln.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('') + '</ul>';
    }

    modalContent.innerHTML = `
        <div class="detail-section ti-title-sum">
            <h4>${vuln.title || 'No Title'}</h4>
            <p><strong>Summary:</strong> ${vuln.summary || 'N/A'}</p>
        </div>
        <div class="detail-section ti-desc">
            <p><strong>Full Description:</strong> ${vuln.description || 'N/A'}</p>
        </div>
        <div class="detail-section ti-scores">
            <p><strong>Severity:</strong> <span class="severity-badge ${ (vuln.severity || 'unknown').toLowerCase()}">${vuln.severity || 'Unknown'}</span></p>
            <p><strong>CVSS Score:</strong> ${getBestScoreThreatIntel(vuln)}</p>
            <p><strong>Priority:</strong> ${vuln.priority || 'N/A'}</p>
        </div>
        <div class="detail-section ti-cwe">
            <p><strong>CWE:</strong> ${vuln.cwe && vuln.cwe.id ? `${vuln.cwe.id} - ${vuln.cwe.name || 'N/A'}` : 'N/A'}</p>
            ${vuln.cwe && vuln.cwe.description ? `<p><small>${vuln.cwe.description}</small></p>` : ''}
        </div>
        <div class="detail-section ti-remediation">
            <h4>Remediation Steps:</h4>
            ${(vuln.remediation_steps && vuln.remediation_steps.length > 0) ? '<ul>' + vuln.remediation_steps.map(step => `<li>${step}</li>`).join('') + '</ul>' : '<p>N/A</p>'}
        </div>
        <div class="detail-section ti-impact">
            <p><strong>Impact Assessment:</strong> ${vuln.impact || 'N/A'}</p>
        </div>
        <div class="detail-section ti-exploits">
            <h4>Exploit Information:</h4>
            <p><strong>Count:</strong> ${vuln.exploit_info ? vuln.exploit_info.count : 'N/A'}</p>
            <p><strong>Maturity:</strong> ${vuln.exploit_info ? vuln.exploit_info.maturity : 'N/A'}</p>
            <p><strong>Risk:</strong> ${vuln.exploit_info ? vuln.exploit_info.risk : 'N/A'}</p>
            <p><strong>Risk Assessment:</strong> ${vuln.exploit_info ? vuln.exploit_info.risk_assessment : 'N/A'}</p>
            <p><strong>Links:</p> ${exploitLinksHtml}
        </div>
        <div class="detail-section ti-mitre">
            <h4>MITRE ATT&CK Techniques:</h4>
            ${mitreHtml}
        </div>
        <div class="detail-section ti-actors">
            <h4>Known Threat Actors:</h4>
            <p>${actorsHtml}</p>
        </div>
        <div class="detail-section ti-references">
            <h4>References:</h4>
            ${referencesHtml}
        </div>
    `;

    // Show the modal (using class 'show' as an example)
    modal.classList.add('show'); 
}

// Helper function to get the best score for threat intel cards
function getBestScoreThreatIntel(vuln) {
    if (vuln.cvss_score && vuln.cvss_score !== 'N/A') return vuln.cvss_score;
    if (vuln.nvd_score && vuln.nvd_score !== 'N/A') return vuln.nvd_score; // Assuming nvd_score might be present
    if (vuln.vulners_score && vuln.vulners_score !== 'N/A') return vuln.vulners_score; // Assuming vulners_score might be present
    return 'N/A';
}

// Helper function to truncate text (can be shared or duplicated if not already global)
function truncateText(text, maxLength) {
    if (!text || typeof text !== 'string') return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Helper function to show/hide loading message for threat intel section
function showLoadingMessageThreatIntel(isLoading) {
    const loadingElement = document.getElementById('loading-threat-intel'); // Ensure you have this element
    if (loadingElement) {
        loadingElement.style.display = isLoading ? 'block' : 'none';
    }
}

// Event listener for DOMContentLoaded to load data and set up filters
document.addEventListener('DOMContentLoaded', () => {
    loadThreatIntelligence();
    setupThreatFilters(); // Call setup for filters
});

// --- Filter Logic ---
function setupThreatFilters() {
    const filterContainer = document.getElementById('threat-intel-filters');
    if (!filterContainer) {
        // Create filter container if it doesn't exist
        const mainContainer = document.getElementById('ThreatIntel'); // Assuming ThreatIntel is the main tab content ID
        if(mainContainer) {
            const searchInput = mainContainer.querySelector('#threat-search');
            const newFilterContainer = document.createElement('div');
            newFilterContainer.id = 'threat-intel-filters';
            newFilterContainer.className = 'filters'; // Use existing filter styles
            newFilterContainer.innerHTML = `
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="critical">Critical</button>
                <button class="filter-btn" data-filter="high">High</button>
                <button class="filter-btn" data-filter="medium">Medium</button>
                <button class="filter-btn" data-filter="low">Low</button>
            `;
            if (searchInput && searchInput.parentNode) {
                searchInput.parentNode.insertBefore(newFilterContainer, searchInput.nextSibling);
            } else {
                 mainContainer.insertBefore(newFilterContainer, mainContainer.firstChild);
            }
            initializeThreatFilterButtons(newFilterContainer);
        }
    } else {
        initializeThreatFilterButtons(filterContainer);
    }

    const searchInput = document.getElementById('threat-search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            applyThreatFilters(e.target.value.toLowerCase());
        });
    }
}

function initializeThreatFilterButtons(filterContainer) {
    const filterButtons = filterContainer.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', () => {
            filterButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            applyThreatFilters();
        });
    });
}

function applyThreatFilters(searchTerm = '') {
    const activeFilterButton = document.querySelector('#threat-intel-filters .filter-btn.active');
    const selectedSeverity = activeFilterButton ? activeFilterButton.dataset.filter : 'all';
    const container = document.getElementById('threat-intel-container');
    if(!container) return;

    const allCards = [];
    container.querySelectorAll('.threat-section .threat-intel-grid .threat-card').forEach(card => allCards.push(card));
    
    let cardsToShow = uniqueThreatIntelData;

    if (selectedSeverity !== 'all') {
        cardsToShow = cardsToShow.filter(vuln => (vuln.severity || 'Unknown').toLowerCase() === selectedSeverity);
    }

    if (searchTerm) {
        cardsToShow = cardsToShow.filter(vuln => 
            (vuln.cve_id && vuln.cve_id.toLowerCase().includes(searchTerm)) ||
            (vuln.title && vuln.title.toLowerCase().includes(searchTerm)) ||
            (vuln.summary && vuln.summary.toLowerCase().includes(searchTerm)) ||
            (vuln.description && vuln.description.toLowerCase().includes(searchTerm))
        );
    }
    displayThreatIntelligence(cardsToShow); // Re-render based on filtered data
} 