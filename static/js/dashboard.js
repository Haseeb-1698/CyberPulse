document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard
    initializeDashboard();
    
    // Initialize tab navigation
    initializeTabs();
    
    // Handle hash changes for tab navigation
    window.addEventListener('hashchange', handleHashChange);
    
    // Initial hash handling
    handleHashChange();
    
    // Initialize export dropdown
    initializeExportDropdown();
    
    // Initialize search functionality
    initializeSearch();
});

function initializeDashboard() {
    loadDashboardData();
}

async function loadDashboardData() {
    const VULN_DATA_URL = '/static/data/vulnerabilities_data.json';
    let retries = 0;
    const MAX_RETRIES = 3;

    const fetchVulnData = async (url) => {
        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status} for ${url}`);
            }
            return await response.json(); 
        } catch (error) {
            console.error(`Error fetching ${url}:`, error);
            showError(`Failed to load data from ${url}. ${error.message}`);
            return null;
        }
    };

    try {
        showLoadingMessage(true);
        const vulnerabilitiesData = await fetchVulnData(VULN_DATA_URL);
        
        const globalRemData = typeof remediationData !== 'undefined' ? remediationData : null;

        if (!vulnerabilitiesData) {
            showError('Failed to load critical vulnerability data. Dashboard may be incomplete.');
        }

        if (globalRemData === null) {
            console.warn("Structured remediation data (global variable 'remediationData') is not available. Remediation details might be incomplete.");
        }
        
        // Use globalRemData directly as the map if it's an object (which it is)
        // No need to iterate and build remediationMap if globalRemData is already the CVE-keyed object
        const remediationMap = (globalRemData && typeof globalRemData === 'object' && !Array.isArray(globalRemData)) 
            ? globalRemData 
            : new Map();

        if (globalRemData && Array.isArray(globalRemData)) {
            // This block is if it *was* an array, build the map. Good for fallback if structure changes.
            console.log("Remediation data was an array, building map...");
            globalRemData.forEach(item => {
                if (item && item.cve_id) {
                    remediationMap.set(item.cve_id, item); 
                }
            });
        } else if (globalRemData && typeof globalRemData !== 'object') {
            console.warn("Global remediation data ('remediationData') is available but not an object or array as expected.");
        }

        let mergedData = [];
        if (vulnerabilitiesData && Array.isArray(vulnerabilitiesData)) {
            mergedData = vulnerabilitiesData.map(vuln => {
                const baseVuln = (typeof vuln === 'object' && vuln !== null) ? vuln : { cve_id: 'unknown' }; 
                let mergedVuln = { ...baseVuln };
                // Get from remediationMap (if it was an array and converted) or directly from globalRemData (if it was an object)
                const enhancedRemediation = remediationMap instanceof Map ? remediationMap.get(baseVuln.cve_id) : remediationMap[baseVuln.cve_id];

                if (enhancedRemediation) {
                    mergedVuln = {
                        ...baseVuln,
                        // Prioritize enhanced remediation data
                        title: enhancedRemediation.title || baseVuln.title,
                        summary: enhancedRemediation.summary || baseVuln.summary,
                        description: enhancedRemediation.description || baseVuln.description,
                        severity: enhancedRemediation.severity || baseVuln.severity, // severity from remediation can override
                        cvss_score: enhancedRemediation.cvss_score || baseVuln.cvss_score,
                        cwe: enhancedRemediation.cwe || baseVuln.cwe,
                        remediation_steps: enhancedRemediation.remediation_steps || (baseVuln.ai_remediation ? baseVuln.ai_remediation.remediation_steps : []),
                        impact: enhancedRemediation.impact || baseVuln.impact,
                        priority: enhancedRemediation.priority || baseVuln.priority, // priority from remediation
                        references: enhancedRemediation.references || baseVuln.references,
                        mitre_techniques: enhancedRemediation.mitre_techniques || (baseVuln.mitre_data ? baseVuln.mitre_data.techniques : []),
                        threat_actors: enhancedRemediation.threat_actors || (baseVuln.mitre_data ? baseVuln.mitre_data.actors : []),
                        exploit_info: enhancedRemediation.exploit_info || baseVuln.exploit_info,
                        ai_remediation: enhancedRemediation.ai_remediation || baseVuln.ai_remediation, // Fallback for ai_remediation if not in enhanced
                    };
                }
                mergedVuln.severity = mergedVuln.severity || mergedVuln.predicted_severity || 'Unknown';
                return mergedVuln;
            });
        } else {
            console.warn("Vulnerability data is not in the expected array format or is null.");
            if (globalRemData === null) {
                 showError('Failed to load dashboard data. Please check the data sources and try again.');
                 showLoadingMessage(false);
                 return; 
            }
        }

        // Deduplicate mergedData based on CVE ID (normalized to uppercase)
        const seenCVEsDashboard = new Map();
        const uniqueMergedData = [];
        mergedData.forEach(vuln => {
            if (vuln && vuln.cve_id && typeof vuln.cve_id === 'string') {
                const normalizedCVE = vuln.cve_id.toUpperCase();
                if (!seenCVEsDashboard.has(normalizedCVE)) {
                    seenCVEsDashboard.set(normalizedCVE, true);
                    uniqueMergedData.push(vuln);
                }
            } else {
                // If cve_id is missing or not a string, decide whether to include it or log an issue
                // For now, we'll include it if it doesn't fit the CVE pattern for deduplication
                // but you might want to filter these out or handle them differently.
                uniqueMergedData.push(vuln); 
            }
        });

        if (mergedData.length === 0 && vulnerabilitiesData === null && globalRemData === null) {
             showError('Failed to load any dashboard data. Please check data sources.');
             showLoadingMessage(false);
             return;
        }
        
        updateDashboardUI({ vulnerabilities: uniqueMergedData });
        console.log('Dashboard data processed.');
        retries = 0;
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        retries++;
        if (retries >= MAX_RETRIES) {
            showError('Failed to load dashboard data after multiple retries. Please check the console for details.');
            console.error('Max retries reached for loading dashboard data.');
        } else {
            showError(`Error loading dashboard data. Retrying in 5 seconds... (Attempt ${retries}/${MAX_RETRIES})`);
            setTimeout(loadDashboardData, 5000);
        }
    } finally {
        showLoadingMessage(false);
    }
}

function updateDashboardUI(data) {
    // Assuming 'data' now contains a 'vulnerabilities' array with merged information
    const vulnerabilities = data.vulnerabilities || [];

    if (!Array.isArray(vulnerabilities)) {
        console.error("Data passed to updateDashboardUI is not in the expected format or vulnerabilities array is missing:", data);
        showError("Received invalid data format for UI update.");
        return;
    }
    
    // Update severity counts
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    vulnerabilities.forEach(vuln => {
        // Severity is now guaranteed to exist due to defaulting in the merge logic
        const severity = vuln.severity; 
        if (severityCounts.hasOwnProperty(severity)) {
            severityCounts[severity]++;
        } else {
            severityCounts['Unknown']++; 
        }
    });
    updateSeverityCounts(severityCounts);

    // Update vulnerability list (assuming you have a function for this)
    updateVulnerabilityList(vulnerabilities); // This function will need to use the merged data

    // Update threat intelligence sections (if separate from vulnerability list)
    // updateThreatIntelligence(vulnerabilities); // This function will also need to use merged data

    // Update trend chart
    const trendData = generateTrendData(vulnerabilities);
    updateTrendChart(trendData);
    
    // Update distribution chart
    updateDistributionChart(severityCounts);
    
    console.log("Dashboard UI updated with new data.");
}

function updateSeverityCounts(counts) {
    Object.entries(counts).forEach(([severity, count]) => {
        const element = document.querySelector(`.stat-card.${severity.toLowerCase()} .stat-value`);
        if (element) {
            element.textContent = count;
        }
    });
}

function updateVulnerabilityList(vulnerabilities) {
    const tables = {
        'all-vulns-table': vulnerabilities,
        'critical-vulns': vulnerabilities.filter(v => v.severity === 'Critical'),
        'high-vulns': vulnerabilities.filter(v => v.severity === 'High'),
        'medium-vulns': vulnerabilities.filter(v => v.severity === 'Medium'),
        'low-vulns': vulnerabilities.filter(v => v.severity === 'Low')
    };

    Object.entries(tables).forEach(([tableId, vulns]) => {
        const tbody = document.querySelector(`#${tableId} tbody`);
        if (tbody) {
            tbody.innerHTML = '';
            vulns.forEach((vuln, idx) => {
                const rowId = `${tableId}-row-${idx}`;
                const detailsRowId = `${tableId}-details-${idx}`;
                const row = createVulnerabilityRow(vuln, rowId, detailsRowId);
                const detailsRow = createVulnerabilityDetailsRow(vuln, detailsRowId);
                tbody.appendChild(row);
                tbody.appendChild(detailsRow);
            });
        }
    });
}

function createVulnerabilityRow(vuln, rowId, detailsRowId) {
    const row = document.createElement('tr');
    row.id = rowId;
    row.style.cursor = 'pointer';
    
    const cvssScore = getBestScore(vuln); // Use helper for best score
    // Severity is now guaranteed to be set, defaulting to 'Unknown' if necessary by the merge logic
    const severity = vuln.severity; 
    const severityClass = `badge-mini ${severity.toLowerCase()}`;
    
    row.innerHTML = `
        <td>${vuln.cve_id || 'N/A'}</td>
        <td><span class="${severityClass}">${severity}</span></td>
        <td>${cvssScore}</td>
        <td>${truncateText(vuln.description, 80)}</td>
        <td>
            <div class="table-actions">
                <button class="table-action-btn" onclick="showVulnerabilityDetails('${vuln.cve_id}')">
                    <i class="fas fa-info-circle"></i>
                </button>
                <button class="table-action-btn" onclick="showThreatIntelModal('${vuln.cve_id}')">
                    <i class="fas fa-shield-alt"></i>
                </button>
            </div>
        </td>
    `;
    
    row.addEventListener('click', function(e) {
        if (e.target.closest('.table-action-btn')) return;
        const detailsRow = document.getElementById(detailsRowId);
        if (detailsRow) {
            detailsRow.style.display = detailsRow.style.display === 'table-row' ? 'none' : 'table-row';
        }
    });
    
    return row;
}

function truncateText(text, maxLength) {
    if (!text) return 'No description available';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

function createVulnerabilityDetailsRow(vuln, detailsRowId) {
    const detailsRow = document.createElement('tr');
    detailsRow.id = detailsRowId;
    detailsRow.className = 'details-row';
    detailsRow.style.display = 'none';
    
    // Create remediation steps list
    let remediationStepsList = '<p>No remediation steps available</p>';
    if (vuln.remediation_steps && vuln.remediation_steps.length > 0) {
        remediationStepsList = `
            <ol>
                ${vuln.remediation_steps.map(step => `<li>${step}</li>`).join('')}
            </ol>
        `;
    }
    
    // Create exploit links list
    let exploitLinksList = '<p>No exploit links available</p>';
    if (vuln.exploit_info && vuln.exploit_info.links && vuln.exploit_info.links.length > 0) {
        exploitLinksList = `
            <ul>
                ${vuln.exploit_info.links.map(link => `<li><a href="${link}" target="_blank">${link}</a></li>`).join('')}
            </ul>
        `;
    }
    
    // Create MITRE techniques list
    let mitreTechniquesList = '<p>No MITRE techniques available</p>';
    if (vuln.mitre_techniques && vuln.mitre_techniques.length > 0) {
        mitreTechniquesList = `
            <ul>
                ${vuln.mitre_techniques.map(tech => `<li>${tech.id}: ${tech.name} (Relevance: ${tech.relevance})</li>`).join('')}
            </ul>
        `;
    }
    
    detailsRow.innerHTML = `
                    <td colspan="6">
                        <div class="details-content">
                <div class="details-section">
                    <h4>Summary</h4>
                    <p>${vuln.summary || 'No summary available'}</p>
                </div>
                
                            <div class="details-section">
                                <h4>Description</h4>
                                <p>${vuln.description || 'No description available'}</p>
                            </div>
                
                            <div class="details-section">
                                <h4>Remediation Steps</h4>
                    ${remediationStepsList}
                            </div>
                
                <div class="details-section">
                    <h4>MITRE ATT&CK Techniques</h4>
                    ${mitreTechniquesList}
                </div>
                
                <div class="details-section">
                    <h4>Threat Actors</h4>
                    <p>${vuln.threat_actors ? vuln.threat_actors.join(', ') : 'No threat actors information available'}</p>
                </div>
                
                <div class="details-section">
                    <h4>Exploit Information</h4>
                    <p><strong>Count:</strong> ${vuln.exploit_info?.count || 'Unknown'}</p>
                    <p><strong>Maturity:</strong> ${vuln.exploit_info?.maturity || 'Unknown'}</p>
                    <p><strong>Risk:</strong> ${vuln.exploit_info?.risk || 'Unknown'}</p>
                    ${vuln.exploit_info?.risk_assessment ? `<p><strong>Risk Assessment:</strong> ${vuln.exploit_info.risk_assessment}</p>` : ''}
                    
                    <h5>Exploit Links:</h5>
                    ${exploitLinksList}
                </div>
                        </div>
                    </td>
    `;
    
    return detailsRow;
}

function updateThreatIntelligence(vulnerabilities) {
    const container = document.getElementById('threat-intel-container');
    if (!container) return;
    
    // Clear previous content
    container.innerHTML = '';
    
    // Group vulnerabilities by severity
    const groupedVulns = {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
    };

    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity || 'Low';
        if (groupedVulns[severity]) {
            groupedVulns[severity].push(vuln);
        }
    });

    // Add filtering controls
        container.innerHTML = `
        <div class="filters">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="critical">Critical</button>
            <button class="filter-btn" data-filter="high">High</button>
            <button class="filter-btn" data-filter="medium">Medium</button>
            <button class="filter-btn" data-filter="low">Low</button>
                </div>
        <div class="threat-intelligence-grid"></div>
    `;
    
    const grid = container.querySelector('.threat-intelligence-grid');
    
    // Create sections for each severity
    Object.entries(groupedVulns).forEach(([severity, vulns]) => {
        if (vulns.length > 0) {
            const section = document.createElement('div');
            section.className = `threat-section ${severity.toLowerCase()}`;
            section.innerHTML = `
                <h3 class="section-title">${severity} Severity Vulnerabilities (${vulns.length})</h3>
                <div class="threat-intel-grid" id="threat-grid-${severity.toLowerCase()}"></div>
            `;
            grid.appendChild(section);

            const threatGrid = section.querySelector(`#threat-grid-${severity.toLowerCase()}`);
            vulns.forEach(vuln => {
                threatGrid.appendChild(createThreatCard(vuln));
            });
        }
    });
    
    // Add event listeners to filter buttons
    const filterButtons = container.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons
            filterButtons.forEach(btn => btn.classList.remove('active'));
            // Add active class to clicked button
            button.classList.add('active');
            
            const filter = button.getAttribute('data-filter');
            const sections = container.querySelectorAll('.threat-section');
            
            sections.forEach(section => {
                if (filter === 'all' || section.classList.contains(filter)) {
                    section.style.display = 'block';
                } else {
                    section.style.display = 'none';
                }
            });
        });
    });
}

function createThreatCard(vuln) {
    const card = document.createElement('div');
    card.className = 'threat-card';
    
    // Get exploit info
    const exploitCount = vuln.exploit_info?.count || 0;
    const exploitMaturity = vuln.exploit_info?.maturity || 'Unknown';
    const exploitRisk = vuln.exploit_info?.risk || 'Unknown';
    
    card.innerHTML = `
            <div class="threat-header">
            <h3>${vuln.cve_id}</h3>
            <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            </div>
                <div class="detail-row">
                    <span class="label">CVSS Score:</span>
            <span>${vuln.cvss_score || 'N/A'}</span>
                </div>
                <div class="detail-row">
            <span class="label">Priority:</span>
            <span>${vuln.priority || 'N/A'}</span>
                </div>
        <div class="detail-row">
            <span class="label">Exploit Count:</span>
            <span>${exploitCount}</span>
        </div>
        <div class="detail-row">
            <span class="label">Exploit Risk:</span>
            <span>${exploitRisk}</span>
        </div>
        <div class="detail-section">
            <h4>Title</h4>
            <p>${vuln.title || 'No title available'}</p>
        </div>
        <div class="detail-section">
            <h4>Summary</h4>
            <p>${truncateText(vuln.summary, 150)}</p>
        </div>
    `;
    
    // Add event listener to show details in modal
    card.addEventListener('click', () => {
        showThreatIntelModal(vuln.cve_id);
    });
    
    return card;
}

function showThreatIntelModal(cveId) {
    const vuln = remediationData[cveId];
    if (!vuln) {
        console.error(`Vulnerability with CVE ID ${cveId} not found`);
        return;
    }
    
    const modal = document.getElementById('threatIntelModal');
    const modalTitle = modal.querySelector('.modal-title span');
    const modalContent = document.getElementById('modal-ti-content');
    
    modalTitle.textContent = cveId;
    
    // Format exploit links if available
    let exploitLinksHtml = '<p>No exploit links available</p>';
    if (vuln.exploit_info?.links && vuln.exploit_info.links.length > 0) {
        exploitLinksHtml = `
            <ul class="exploit-list">
                ${vuln.exploit_info.links.map(link => 
                    `<li><a href="${link}" target="_blank">${link}</a></li>`
                ).join('')}
            </ul>
        `;
    }
    
    // Format MITRE techniques if available
    let mitreTechniquesHtml = '<p>No MITRE techniques available</p>';
    if (vuln.mitre_techniques && vuln.mitre_techniques.length > 0) {
        mitreTechniquesHtml = `
            <div class="mitre-data">
                ${vuln.mitre_techniques.map(tech => `
                    <div class="mitre-row">
                        <span class="mitre-label">${tech.id}:</span>
                        <span class="mitre-value">${tech.name} (Relevance: ${tech.relevance})</span>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    // Format references if available
    let referencesHtml = '<p>No references available</p>';
    if (vuln.references) {
        const allReferences = [
            ...vuln.references.vendor_advisories || [],
            ...vuln.references.technical_reports || [],
            ...vuln.references.mitre_links || [],
            ...vuln.references.other || []
        ];
        
        if (allReferences.length > 0) {
            referencesHtml = `
                <ul class="reference-list">
                    ${allReferences.map(ref => 
                        `<li><a href="${ref}" target="_blank">${ref}</a></li>`
                    ).join('')}
                </ul>
            `;
        }
    }
    
    modalContent.innerHTML = `
        <div class="detail-section">
            <h4>Title</h4>
            <p>${vuln.title || 'No title available'}</p>
        </div>
        
        <div class="detail-section">
            <h4>Summary</h4>
            <p>${vuln.summary || 'No summary available'}</p>
        </div>
                
                <div class="detail-section">
                    <h4>Description</h4>
                    <p>${vuln.description || 'No description available'}</p>
                </div>
                
                <div class="detail-section">
            <h4>Severity Information</h4>
            <div class="detail-row">
                <span class="label">Severity:</span>
                <span>${vuln.severity || 'N/A'}</span>
            </div>
            <div class="detail-row">
                <span class="label">CVSS Score:</span>
                <span>${vuln.cvss_score || 'N/A'}</span>
            </div>
            <div class="detail-row">
                <span class="label">Priority:</span>
                <span>${vuln.priority || 'N/A'}</span>
            </div>
        </div>
        
        <div class="detail-section">
                    <h4>Remediation Steps</h4>
            ${vuln.remediation_steps ? `
                <ol>
                    ${vuln.remediation_steps.map(step => `<li>${step}</li>`).join('')}
                    </ol>
            ` : '<p>No remediation steps available</p>'}
                </div>
                
                <div class="detail-section">
            <h4>CWE Information</h4>
            ${vuln.cwe ? `
                <div class="detail-row">
                    <span class="label">CWE ID:</span>
                    <span>${vuln.cwe.id || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="label">CWE Name:</span>
                    <span>${vuln.cwe.name || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="label">Description:</span>
                    <span>${vuln.cwe.description || 'N/A'}</span>
                </div>
            ` : '<p>No CWE information available</p>'}
        </div>
        
                <div class="detail-section">
            <h4>Exploit Information</h4>
            <div class="detail-row">
                <span class="label">Exploit Count:</span>
                <span>${vuln.exploit_info?.count || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="label">Maturity:</span>
                <span>${vuln.exploit_info?.maturity || 'Unknown'}</span>
            </div>
            <div class="detail-row">
                <span class="label">Risk:</span>
                <span>${vuln.exploit_info?.risk || 'Unknown'}</span>
            </div>
            ${vuln.exploit_info?.risk_assessment ? `
                <div class="detail-row">
                    <span class="label">Risk Assessment:</span>
                    <span>${vuln.exploit_info.risk_assessment}</span>
                </div>
                ` : ''}
            
            <h5>Exploit Links:</h5>
            ${exploitLinksHtml}
            </div>
        
        <div class="detail-section">
            <h4>MITRE ATT&CK Techniques</h4>
            ${mitreTechniquesHtml}
        </div>
        
        <div class="detail-section">
            <h4>Threat Actors</h4>
            <p>${vuln.threat_actors ? vuln.threat_actors.join(', ') : 'No threat actors information available'}</p>
        </div>
        
        <div class="detail-section">
            <h4>References</h4>
            ${referencesHtml}
        </div>
    `;
    
    modal.classList.add('show');
}

function updateTrendChart(vulnerabilities) {
    const ctx = document.getElementById('trendChart');
    if (!ctx) return;
    
    // Use a simulated trend over time since our data doesn't have actual dates
    // Generate dates for the last 30 days
    const dates = [];
    const now = new Date();
    for (let i = 29; i >= 0; i--) {
        const date = new Date(now);
        date.setDate(date.getDate() - i);
        dates.push(date.toLocaleDateString());
    }
    
    // Generate random counts for each severity level with some logical trend
    // These would be replaced with actual data in a real implementation
    const criticalData = [4, 4, 5, 5, 4, 4, 3, 3, 3, 4, 4, 5, 5, 5, 4, 4, 4, 3, 3, 3, 4, 4, 4, 5, 5, 4, 4, 3, 4, 4];
    const highData = [8, 9, 9, 10, 10, 11, 12, 12, 11, 10, 9, 8, 9, 10, 11, 12, 12, 11, 10, 9, 10, 11, 12, 12, 11, 10, 9, 10, 11, 12];
    const mediumData = [18, 19, 20, 21, 22, 23, 23, 22, 21, 20, 19, 18, 19, 20, 21, 22, 23, 22, 21, 20, 19, 20, 21, 22, 23, 22, 21, 20, 19, 23];
    const lowData = [15, 16, 17, 18, 17, 16, 15, 14, 15, 16, 17, 18, 17, 16, 15, 14, 15, 16, 17, 18, 17, 16, 15, 14, 15, 16, 17, 18, 17, 18];
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: 'white' // Legend label color
                }
            },
            tooltip: {
                titleColor: 'white',
                bodyColor: 'white',
                backgroundColor: 'rgba(30,30,30,0.95)'
            }
        },
        scales: {
            x: {
                ticks: {
                    color: 'white',
                    callback: function(value, index, ticks) {
                        // Show every 4th label
                        return index % 4 === 0 ? this.getLabelForValue(value) : '';
                    }
                },
                grid: {
                    color: 'rgba(255,255,255,0.2)'
                }
            },
            y: {
                ticks: {
                    color: 'white'
                },
                grid: {
                    color: 'rgba(255,255,255,0.2)'
                }
            }
        }
    };
    
    const chartData = {
        labels: dates,
        datasets: [
            {
                label: 'Critical',
                data: criticalData,
                borderColor: 'rgba(255, 77, 79, 1)',
                backgroundColor: 'rgba(255, 77, 79, 0.1)',
                fill: true,
                tension: 0.4
            },
            {
                label: 'High',
                data: highData,
                borderColor: 'rgba(255, 140, 102, 1)',
                backgroundColor: 'rgba(255, 140, 102, 0.1)',
                fill: true,
                tension: 0.4
            },
            {
                label: 'Medium',
                data: mediumData,
                borderColor: 'rgba(255, 170, 0, 1)',
                backgroundColor: 'rgba(255, 170, 0, 0.1)',
                fill: true,
                tension: 0.4
            },
            {
                label: 'Low',
                data: lowData,
                borderColor: 'rgba(0, 204, 153, 1)',
                backgroundColor: 'rgba(0, 204, 153, 0.1)',
                fill: true,
                tension: 0.4
            }
        ]
    };
    
    // Check if chart exists and destroy it before creating a new one
    if (window.trendChart instanceof Chart) {
        window.trendChart.destroy();
    }
    
    // Create new chart
    window.trendChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: chartOptions
    });
}

function updateDistributionChart(severityCounts) {
    const ctx = document.getElementById('distributionChart');
    if (!ctx) return;

    // Create data for the chart
    const chartData = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [
                severityCounts.Critical,
                severityCounts.High,
                severityCounts.Medium,
                severityCounts.Low
            ],
            backgroundColor: [
                'rgba(255, 77, 79, 0.7)',
                'rgba(255, 140, 102, 0.7)',
                'rgba(255, 170, 0, 0.7)',
                'rgba(0, 204, 153, 0.7)'
            ],
            borderColor: [
                'rgba(255, 77, 79, 1)',
                'rgba(255, 140, 102, 1)',
                'rgba(255, 170, 0, 1)',
                'rgba(0, 204, 153, 1)'
            ],
            borderWidth: 1
        }]
    };

    // Check if chart exists and destroy it before creating a new one
    if (window.distributionChart instanceof Chart) {
        window.distributionChart.destroy();
    }

    // Create new chart
    window.distributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: 'white' // ✅ white legend labels
                    }
                },
                title: {
                    display: true,
                    text: 'Vulnerability Distribution by Severity',
                    color: 'white' // ✅ white chart title
                },
                tooltip: {
                    titleColor: 'white',
                    bodyColor: 'white',
                    backgroundColor: 'rgba(30,30,30,0.95)' // ✅ same as trend
                }
            },
            cutout: '70%'
        }
    });
}


function initializeTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const section = this.getAttribute('data-section');
            openSection(section);
        });
    });
}

function handleHashChange() {
    const hash = window.location.hash.substring(1);
    if (hash) {
        openSection(hash);
    } else {
        openSection('All');
    }
}

function openSection(sectionName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Remove active class from all tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected content
    const selectedContent = document.getElementById(sectionName);
    if (selectedContent) {
        selectedContent.classList.add('active');
    }
    
    // Update active tab
    const activeTab = document.querySelector(`.tab[data-section="${sectionName}"]`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    // Update URL hash
    history.pushState(null, null, '#' + sectionName);
}

function initializeExportDropdown() {
    const exportTrigger = document.getElementById('export-dropdown-trigger');
    const exportDropdown = document.getElementById('export-dropdown');
    
    if (exportTrigger && exportDropdown) {
        exportTrigger.addEventListener('click', function(e) {
            e.preventDefault();
            exportDropdown.classList.toggle('show');
        });

        document.addEventListener('click', function(e) {
            if (!exportTrigger.contains(e.target) && !exportDropdown.contains(e.target)) {
                exportDropdown.classList.remove('show');
            }
        });
    }
}

function initializeSearch() {
    const searchInput = document.getElementById('vuln-search');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
    const searchTerm = this.value.toLowerCase();
            const table = document.getElementById('all-vulns-table');
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr:not(.details-row)');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
                const isVisible = text.includes(searchTerm);
                
                // Get the associated details row
                const rowId = row.id;
                const detailsRowId = rowId.replace('row', 'details');
                const detailsRow = document.getElementById(detailsRowId);
                
                if (isVisible) {
            row.style.display = '';
                    if (detailsRow) {
                        // Keep the details row in its current display state
                        // Don't change it to keep expanded rows expanded
                    }
        } else {
            row.style.display = 'none';
                    if (detailsRow) {
                        detailsRow.style.display = 'none';
                    }
        }
    });
});
    }
    
    // Also add search for threat intel
    const threatSearch = document.getElementById('threat-search');
    if (threatSearch) {
        threatSearch.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const container = document.getElementById('threat-intel-container');
            if (!container) return;
            
            const cards = container.querySelectorAll('.threat-card');
            
            let visibleCards = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };

            cards.forEach(card => {
                const text = card.textContent.toLowerCase();
                const isVisible = text.includes(searchTerm);
                const section = card.closest('.threat-section');
                
                if (isVisible) {
                    card.style.display = '';
                    
                    // Track visible cards per severity
                    if (section) {
                        const severity = section.getAttribute('data-severity');
                        if (severity && visibleCards[severity] !== undefined) {
                            visibleCards[severity]++;
                        }
                    }
                } else {
                    card.style.display = 'none';
                }
            });
            
            // Show/hide sections based on visible cards
            const sections = container.querySelectorAll('.threat-section');
            sections.forEach(section => {
                const severity = section.getAttribute('data-severity');
                section.style.display = (severity && visibleCards[severity] > 0) ? '' : 'none';
            });
        });
    }
}

function showError(message) {
    console.error(message);
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.style.backgroundColor = '#ff4d4f';
    errorDiv.style.color = 'white';
    errorDiv.style.padding = '10px';
    errorDiv.style.marginBottom = '15px';
    errorDiv.style.borderRadius = '4px';
    errorDiv.textContent = message;
    
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.insertBefore(errorDiv, mainContent.firstChild);
        
        // Auto-remove the error after 5 seconds
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
}

// Close modal when clicking the close button
document.addEventListener('DOMContentLoaded', function() {
    const closeModalButton = document.getElementById('closeModal');
    if (closeModalButton) {
        closeModalButton.addEventListener('click', function() {
            document.getElementById('threatIntelModal').classList.remove('show');
        });
    }
    
    // Also close when clicking outside the modal
    const modal = document.getElementById('threatIntelModal');
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.classList.remove('show');
            }
        });
    }
});

// Function to show vulnerability details (can be called from HTML)
function showVulnerabilityDetails(cveId) {
    const vuln = remediationData[cveId];
    if (!vuln) {
        console.error(`Vulnerability with CVE ID ${cveId} not found`);
        return;
    }
    
    // Find the row that contains this vulnerability
    const rows = document.querySelectorAll('tr');
    for (let i = 0; i < rows.length; i++) {
        if (rows[i].textContent.includes(cveId)) {
            const rowId = rows[i].id;
            if (rowId) {
                const detailsRowId = rowId.replace('row', 'details');
                const detailsRow = document.getElementById(detailsRowId);
                if (detailsRow) {
                    detailsRow.style.display = 'table-row';
                    
                    // Scroll to the details row
                    detailsRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }
            break;
        }
    }
}

// Helper function to show/hide loading message (implement as needed)
function showLoadingMessage(isLoading) {
    const loadingElement = document.getElementById('loading-dashboard-data'); // Ensure you have this element
    if (loadingElement) {
        loadingElement.style.display = isLoading ? 'block' : 'none';
    }
}

// Helper to get the best score
function getBestScore(vuln) {
    if (vuln.cvss_score && vuln.cvss_score !== 'N/A') return vuln.cvss_score;
    if (vuln.nvd_score && vuln.nvd_score !== 'N/A') return vuln.nvd_score;
    if (vuln.vulners_score && vuln.vulners_score !== 'N/A') return vuln.vulners_score;
    return 'N/A';
}

// Helper to truncate text
function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Define generateTrendData function
function generateTrendData(vulnerabilities) {
    // Placeholder: Implement your actual trend data generation logic here
    // This example groups by severity for the last 7 "days" (mocked)
    const trend = {
        labels: Array.from({length: 7}, (_, i) => `Day ${i + 1}`),
        datasets: [
            { label: 'Critical', data: new Array(7).fill(0), borderColor: '#ff4d4f', backgroundColor: 'rgba(255, 77, 79, 0.1)', tension: 0.1, fill: true },
            { label: 'High', data: new Array(7).fill(0), borderColor: '#ff8c66', backgroundColor: 'rgba(255, 140, 102, 0.1)', tension: 0.1, fill: true },
            { label: 'Medium', data: new Array(7).fill(0), borderColor: '#ffaa00', backgroundColor: 'rgba(255, 170, 0, 0.1)', tension: 0.1, fill: true },
            { label: 'Low', data: new Array(7).fill(0), borderColor: '#00cc99', backgroundColor: 'rgba(0, 204, 153, 0.1)', tension: 0.1, fill: true },
            { label: 'Unknown', data: new Array(7).fill(0), borderColor: '#7a8aa6', backgroundColor: 'rgba(122, 138, 166, 0.1)', tension: 0.1, fill: true }
        ]
    };

    if (!vulnerabilities || vulnerabilities.length === 0) return trend;

    // Example: Distribute vulnerabilities somewhat randomly over the 7 days for mock trend
    vulnerabilities.forEach(vuln => {
        const dayIndex = Math.floor(Math.random() * 7);
        const severity = vuln.severity || 'Unknown';
        const dataset = trend.datasets.find(ds => ds.label === severity);
        if (dataset) {
            dataset.data[dayIndex]++;
        }
    });
    return trend;
}