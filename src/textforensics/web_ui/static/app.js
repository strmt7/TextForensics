/**
 * TextForensics Web UI - Real-time Analysis & Visualization
 */

// State management
const state = {
    history: [],
    currentAnalysis: null,
    secondAnalysis: null,
    ws: null,
    isStreaming: true,
    charts: {
        gauge: null,
        detector: null
    },
    serverHistory: [],
    compareMode: false
};

// DOM Elements
const elements = {
    textInput: document.getElementById('textInput'),
    analyzeBtn: document.getElementById('analyzeBtn'),
    clearBtn: document.getElementById('clearBtn'),
    streamToggle: document.getElementById('streamToggle'),
    wordCount: document.getElementById('wordCount'),
    charCount: document.getElementById('charCount'),
    resultsPanel: document.getElementById('resultsPanel'),
    consensusVerdict: document.getElementById('consensusVerdict'),
    consensusConfidence: document.getElementById('consensusConfidence'),
    trustCoverage: document.getElementById('trustCoverage'),
    trustDetails: document.getElementById('trustDetails'),
    familyCount: document.getElementById('familyCount'),
    familyDetails: document.getElementById('familyDetails'),
    analysisTime: document.getElementById('analysisTime'),
    gaugeChart: document.getElementById('gaugeChart'),
    detectorChart: document.getElementById('detectorChart'),
    detectorList: document.getElementById('detectorList'),
    trustMap: document.getElementById('trustMap'),
    verdictDisplay: document.getElementById('verdictDisplay'),
    historyList: document.getElementById('historyList'),
    warningsList: document.getElementById('warningsList'),
    rawData: document.getElementById('rawData'),
    versionDisplay: document.getElementById('versionDisplay'),
    btnText: document.querySelector('.btn-text'),
    btnLoader: document.querySelector('.btn-loader'),
    // New elements
    exportJsonBtn: document.getElementById('exportJsonBtn'),
    exportCsvBtn: document.getElementById('exportCsvBtn'),
    exportHtmlBtn: document.getElementById('exportHtmlBtn'),
    compareBtn: document.getElementById('compareBtn'),
    loadHistoryBtn: document.getElementById('loadHistoryBtn'),
    closeCompareBtn: document.getElementById('closeCompareBtn'),
    compareView: document.getElementById('compareView'),
    compareASummary: document.getElementById('compareASummary'),
    compareBSummary: document.getElementById('compareBSummary'),
    compareDetectors: document.getElementById('compareDetectors'),
    compareTrustMap: document.getElementById('compareTrustMap'),
    compareVerdict: document.getElementById('compareVerdict')
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateInputStats();
    setupEventListeners();
    loadVersion();
});

// Event Listeners
function setupEventListeners() {
    elements.textInput.addEventListener('input', updateInputStats);

    elements.analyzeBtn.addEventListener('click', handleAnalyze);

    elements.clearBtn.addEventListener('click', handleClear);

    elements.streamToggle.addEventListener('change', (e) => {
        state.isStreaming = e.target.checked;
    });

    // Export buttons
    elements.exportJsonBtn.addEventListener('click', () => exportAnalysis('json'));
    elements.exportCsvBtn.addEventListener('click', () => exportAnalysis('csv'));
    elements.exportHtmlBtn.addEventListener('click', () => exportAnalysis('html'));

    // Compare
    elements.compareBtn.addEventListener('click', toggleCompareMode);
    elements.closeCompareBtn.addEventListener('click', closeCompareView);

    // Server history
    elements.loadHistoryBtn.addEventListener('click', loadServerHistory);
}

// Update input statistics
function updateInputStats() {
    const text = elements.textInput.value;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    const chars = text.length;

    elements.wordCount.textContent = `${words} word${words !== 1 ? 's' : ''}`;
    elements.charCount.textContent = `${chars} character${chars !== 1 ? 's' : ''}`;
}

// Load version
async function loadVersion() {
    try {
        const response = await fetch('/version');
        const data = await response.json();
        elements.versionDisplay.textContent = data.version;
    } catch (e) {
        elements.versionDisplay.textContent = '0.2.0';
    }
}

// Handle analyze button click
async function handleAnalyze() {
    const text = elements.textInput.value.trim();
    if (!text) {
        alert('Please enter some text to analyze.');
        return;
    }

    setAnalyzing(true);
    clearResults();

    if (state.isStreaming) {
        await analyzeWithWebSocket(text);
    } else {
        await analyzeWithREST(text);
    }

    setAnalyzing(false);
}

// Set analyzing state
function setAnalyzing(analyzing) {
    elements.analyzeBtn.disabled = analyzing;
    elements.btnText.classList.toggle('hidden', analyzing);
    elements.btnLoader.classList.toggle('hidden', !analyzing);
}

// Clear results
function clearResults() {
    elements.resultsPanel.classList.add('hidden');
    destroyCharts();
}

// Handle WebSocket analysis
async function analyzeWithWebSocket(text) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(`ws://${window.location.host}/ws/analyze`);
        state.ws = ws;

        const detectorResults = [];
        let startTime = Date.now();

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'analyze', text }));
        };

        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);

            switch (message.type) {
                case 'started':
                    break;

                case 'detector_result':
                    detectorResults.push(message.data);
                    updateStreamingDetectorList(detectorResults);
                    break;

                case 'complete':
                    const elapsed = Date.now() - startTime;
                    handleCompleteAnalysis(message.data, elapsed);
                    ws.close();
                    resolve();
                    break;

                case 'error':
                    ws.close();
                    reject(new Error(message.message));
                    break;
            }
        };

        ws.onerror = (error) => {
            reject(new Error('WebSocket connection failed'));
        };

        ws.onclose = () => {
            state.ws = null;
        };
    });
}

// Handle REST API analysis
async function analyzeWithREST(text) {
    const startTime = Date.now();

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });

        const result = await response.json();
        const elapsed = Date.now() - startTime;

        if (!result.success) {
            throw new Error(result.error || 'Analysis failed');
        }

        handleCompleteAnalysis(result.data, elapsed);
    } catch (error) {
        alert(`Analysis failed: ${error.message}`);
        throw error;
    }
}

// Update detector list during streaming
function updateStreamingDetectorList(results) {
    renderDetectorList(results);
    updateDetectorChart(results);
}

// Handle complete analysis result
function handleCompleteAnalysis(data, elapsedMs) {
    state.currentAnalysis = data;

    // Show results panel
    elements.resultsPanel.classList.remove('hidden');

    // Update metrics
    updateMetrics(data, elapsedMs);

    // Render visualizations
    renderGaugeChart(data);
    renderDetectorChart(data.consensus);
    renderDetectorList(data.detector_results);
    renderTrustMap(data.trust_map);
    renderVerdictDisplay(data);
    renderWarnings(data);
    renderRawData(data);

    // Add to history
    addToHistory(data);

    // Scroll to results
    elements.resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Canonical ensemble probability (IF-04). The server bundle exposes
// `consensus.calibrated_ai_probability` together with
// `consensus.ensemble_calibration_id`; a top-level AI-authorship
// probability is shown ONLY when both are present and the value is a
// finite number in [0, 1]. Anything else is unavailable -- never a
// verdict-derived 85/15/50 substitute, and never a read of the
// legacy uncalibrated field name (no such field exists in the
// canonical bundle). A missing calibrated probability stays
// missing/abstained in every surface below.
function calibratedEnsembleProbability(consensus) {
    if (!consensus) return null;
    const value = consensus.calibrated_ai_probability;
    const calibrationId = consensus.ensemble_calibration_id;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) return null;
    if (typeof calibrationId !== 'string' || calibrationId.length === 0) return null;
    return { value, calibrationId };
}

// Exact calibrated value plus its calibration identity, or null when
// no calibrated ensemble probability is available.
function formatCalibratedProbability(consensus) {
    const calibrated = calibratedEnsembleProbability(consensus);
    if (!calibrated) return null;
    return `${(calibrated.value * 100).toFixed(1)}% (calibration: ${calibrated.calibrationId})`;
}

// Update top metrics
function updateMetrics(data, elapsedMs) {
    const consensus = data.consensus;
    const trustMap = data.trust_map;

    // Consensus verdict
    elements.consensusVerdict.textContent = formatVerdict(consensus.verdict);
    elements.consensusVerdict.className = `metric-value verdict-${consensus.verdict}`;

    const calibrated = formatCalibratedProbability(consensus);
    if (calibrated !== null) {
        elements.consensusConfidence.textContent = `AI Probability: ${calibrated}`;
    } else {
        elements.consensusConfidence.textContent = `Families agreeing: ${consensus.independent_families || 0}`;
    }

    // Trust coverage
    elements.trustCoverage.textContent = formatTrustState(trustMap.overall);
    elements.trustCoverage.className = `metric-value trust-${trustMap.overall}`;
    elements.trustDetails.textContent = `${trustMap.dimensions?.filter(d => d.state === 'supported').length || 0} of ${trustMap.dimensions?.length || 0} dimensions supported`;

    // Family count
    elements.familyCount.textContent = consensus.independent_families || 0;
    elements.familyDetails.textContent = `${data.detector_results?.length || 0} detectors total`;

    // Analysis time
    elements.analysisTime.textContent = `${elapsedMs}ms`;
}

// Format verdict for display
function formatVerdict(verdict) {
    const labels = {
        'ai_like': 'AI-like',
        'human_like': 'Human-like',
        'abstain': 'Abstain',
        'insufficient_evidence': 'Insufficient Evidence',
        'mixed': 'Mixed'
    };
    return labels[verdict] || verdict;
}

// Format trust state
function formatTrustState(state) {
    const labels = {
        'strong': 'Strong',
        'supported': 'Supported',
        'partial': 'Partial',
        'mixed': 'Mixed',
        'insufficient': 'Insufficient',
        'unknown': 'Unknown',
        'out_of_scope': 'Out of Scope'
    };
    return labels[state] || state;
}

// Gauge Chart
function renderGaugeChart(data) {
    const ctx = elements.gaugeChart.getContext('2d');

    // Determine AI probability: only the canonical calibrated
    // ensemble probability counts (IF-04). Without it there is no
    // numerical authorship probability to draw -- no 85/15/50
    // verdict substitute.
    const calibrated = calibratedEnsembleProbability(data.consensus);
    const aiProb = calibrated !== null ? calibrated.value * 100 : null;

    // Destroy existing chart
    if (state.charts.gauge) {
        state.charts.gauge.destroy();
    }

    state.charts.gauge = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: aiProb !== null ? [aiProb, 100 - aiProb] : [0, 100],
                backgroundColor: [
                    aiProb !== null ? getGaugeColor(aiProb) : 'rgba(255,255,255,0.05)',
                    'rgba(255,255,255,0.05)'
                ],
                borderWidth: 0,
                circumference: 180,
                rotation: 270
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '75%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        }
    });

    // Add center text
    const originalDraw = state.charts.gauge.draw;
    state.charts.gauge.draw = function(...args) {
        originalDraw.apply(this, args);

        const ctx = this.ctx;
        const centerX = this.chartArea.left + this.chartArea.width / 2;
        const centerY = this.chartArea.top + this.chartArea.height / 2 + 20;

        ctx.save();
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.font = 'bold 36px system-ui';
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text').trim() || '#f4f7fa';
        ctx.fillText(aiProb !== null ? `${aiProb.toFixed(1)}%` : 'N/A', centerX, centerY);

        ctx.font = '12px system-ui';
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted').trim() || '#9aa4af';
        ctx.fillText(
            aiProb !== null ? `AI Probability (calibration: ${calibrated.calibrationId})` : 'AI Probability: not calibrated',
            centerX, centerY + 30
        );
        ctx.restore();
    };

    state.charts.gauge.update();
}

function getGaugeColor(prob) {
    if (prob < 30) return '#22c55e';
    if (prob < 70) return '#f59e0b';
    return '#ef4444';
}

// Detector Breakdown Chart
function renderDetectorChart(consensus) {
    const ctx = elements.detectorChart.getContext('2d');

    // Prepare data from family votes. A missing family calibration
    // is N/A (a gap in the chart), not a 50% substitute (IF-04).
    const families = consensus.family_votes || [];
    const labels = families.map(f => f.detector_family.replace(/-/g, ' '));
    const scores = families.map(f => {
        const value = f.calibrated_ai_probability;
        return (typeof value === 'number' && Number.isFinite(value)) ? value * 100 : null;
    });
    const colors = scores.map(s => s === null ? 'rgba(255,255,255,0.15)' : getGaugeColor(s));

    if (state.charts.detector) {
        state.charts.detector.destroy();
    }

    state.charts.detector = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Calibrated AI probability % (uncalibrated: N/A)',
                data: scores,
                backgroundColor: colors,
                borderRadius: 6,
                maxBarThickness: 50
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ctx.raw === null || ctx.raw === undefined ? 'Not calibrated' : `${ctx.dataset.label}: ${ctx.raw.toFixed(1)}%`
                    }
                }
            },
            scales: {
                x: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted').trim(), font: { size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text').trim(), font: { size: 12 } }
                }
            }
        }
    });
}

// Detector List
function renderDetectorList(results) {
    const container = elements.detectorList;

    if (!results || results.length === 0) {
        container.innerHTML = '<div class="detector-empty">No detector results</div>';
        return;
    }

    container.innerHTML = results.map((result, index) => {
        const isFailed = result.failed === true;
        const score = isFailed ? null : result.score;
        const verdict = isFailed ? 'error' : (result.verdict || 'unknown');
        const calibrated = result.calibrated_ai_probability;

        let displayScore = '—';
        let scorePercent = 0;

        if (calibrated !== null && calibrated !== undefined) {
            displayScore = `${(calibrated * 100).toFixed(1)}%`;
            scorePercent = calibrated * 100;
        } else if (score !== null && score !== undefined) {
            // Native instrument score: show the raw value with native
            // semantics only, never as a probability percentage, and
            // draw no probability-like bar for it (IF-04).
            const raw = Number(score);
            displayScore = Number.isFinite(raw) ? `native ${raw.toFixed(3)}` : '—';
            scorePercent = 0;
        }

        return `
            <div class="detector-item">
                <div class="detector-info">
                    <div class="detector-name">${escapeHtml(result.detector_id)}</div>
                    <div class="detector-meta">
                        v${escapeHtml(result.detector_version)} • ${escapeHtml(result.detector_family)} • ${escapeHtml(result.execution || 'local')}
                    </div>
                </div>
                <div class="detector-score">
                    <div class="score-bar">
                        <div class="score-bar-fill" style="width: ${scorePercent}%; background: ${getGaugeColor(scorePercent)}"></div>
                    </div>
                    <div class="score-value">${displayScore}</div>
                    <span class="verdict-badge ${verdict}">${formatVerdict(verdict)}</span>
                </div>
            </div>
        `;
    }).join('');
}

// Trust Map Visualization
function renderTrustMap(trustMap) {
    const container = elements.trustMap;

    if (!trustMap || !trustMap.dimensions) {
        container.innerHTML = '<div class="trust-empty">Trust map data unavailable</div>';
        return;
    }

    container.innerHTML = trustMap.dimensions.map(dim => `
        <div class="trust-dimension">
            <div class="dimension-header">
                <span class="dimension-name">${escapeHtml(dim.dimension.replace(/_/g, ' '))}</span>
                <span class="dimension-state ${dim.state}">${formatTrustState(dim.state)}</span>
            </div>
            <div class="dimension-reason">${escapeHtml(dim.reason)}</div>
        </div>
    `).join('');
}

// Verdict Display
function renderVerdictDisplay(data) {
    const container = elements.verdictDisplay;
    const consensus = data.consensus;
    const input = data.input;

    const verdictClass = `verdict-${consensus.verdict}`;

    container.innerHTML = `
        <div class="verdict-card">
            <h4>Consensus Summary</h4>
            <div class="verdict-row">
                <span class="verdict-key">Final Verdict</span>
                <span class="verdict-value ${verdictClass}">${formatVerdict(consensus.verdict)}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Independent Families</span>
                <span class="verdict-value">${consensus.independent_families || 0}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Family Agreement</span>
                <span class="verdict-value">${consensus.family_agreement !== null ? (consensus.family_agreement * 100).toFixed(1) + '%' : 'N/A'}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Calibrated Families</span>
                <span class="verdict-value">${consensus.calibrated_families || 0}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">AI Probability</span>
                <span class="verdict-value">${formatCalibratedProbability(consensus) ?? 'Not calibrated'}</span>
            </div>
        </div>
        <div class="verdict-card">
            <h4>Input Statistics</h4>
            <div class="verdict-row">
                <span class="verdict-key">Word Count</span>
                <span class="verdict-value">${input.word_count || 0}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Sentence Count</span>
                <span class="verdict-value">${input.sentence_count || 0}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Paragraph Count</span>
                <span class="verdict-value">${input.paragraph_count || 0}</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Content Hash</span>
                <span class="verdict-value" style="font-family: monospace; font-size: 11px;">${data.content_sha256?.substring(0, 16) || 'N/A'}…</span>
            </div>
            <div class="verdict-row">
                <span class="verdict-key">Generated</span>
                <span class="verdict-value">${formatDate(data.generated_at_utc)}</span>
            </div>
        </div>
        <div class="verdict-card">
            <h4>Consensus Details</h4>
            ${(consensus.family_votes || []).map(vote => `
                <div class="verdict-row">
                    <span class="verdict-key">${escapeHtml(vote.detector_family.replace(/-/g, ' '))}</span>
                    <span class="verdict-value">
                        ${vote.calibrated_ai_probability !== null ? (vote.calibrated_ai_probability * 100).toFixed(1) + '%' : 'Uncalibrated'}
                        <span class="verdict-badge ${vote.verdict}" style="margin-left: 8px; font-size: 10px;">${formatVerdict(vote.verdict)}</span>
                    </span>
                </div>
            `).join('')}
        </div>
    `;
}

// Warnings
function renderWarnings(data) {
    const container = elements.warningsList;

    const warnings = [
        ...(data.consensus.warnings || []),
        ...(data.detector_results || []).flatMap(d => d.warnings || []),
        ...(data.limitations || [])
    ];

    const uniqueWarnings = [...new Set(warnings)];

    if (uniqueWarnings.length === 0) {
        container.innerHTML = '<div style="color: var(--success);">No warnings or limitations.</div>';
        return;
    }

    container.innerHTML = uniqueWarnings.map(w => `
        <div class="warning-item">
            <span class="warning-icon">⚠</span>
            <span>${escapeHtml(w)}</span>
        </div>
    `).join('');
}

// Raw Data
function renderRawData(data) {
    elements.rawData.textContent = JSON.stringify(data, null, 2);
}

// History
function addToHistory(data) {
    // Store only the canonical calibrated ensemble probability (with
    // its calibration identity); an uncalibrated bundle stores null
    // and renders no percentage (IF-04).
    const calibrated = calibratedEnsembleProbability(data.consensus);
    const historyItem = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        text: elements.textInput.value.trim(),
        preview: elements.textInput.value.trim().substring(0, 100) + (elements.textInput.value.length > 100 ? '…' : ''),
        verdict: data.consensus.verdict,
        aiProbability: calibrated !== null ? calibrated.value : null,
        calibrationId: calibrated !== null ? calibrated.calibrationId : null,
        wordCount: data.input.word_count,
        data: data
    };

    state.history.unshift(historyItem);

    // Keep only last 20 items
    if (state.history.length > 20) {
        state.history = state.history.slice(0, 20);
    }

    renderHistory();
}

function renderHistory() {
    const container = elements.historyList;

    if (state.history.length === 0) {
        container.innerHTML = '<div class="history-empty">No analyses yet. Analyze some text to see history.</div>';
        return;
    }

    container.innerHTML = state.history.map((item, index) => `
        <div class="history-item ${index === 0 ? 'active' : ''}" data-index="${index}">
            <div class="history-preview">
                <div class="history-text">${escapeHtml(item.preview)}</div>
                <div class="history-meta">
                    <span>${escapeHtml(String(item.wordCount ?? 0))} words</span>
                    <span>${formatTime(item.timestamp)}</span>
                </div>
            </div>
            <div class="history-verdict">
                <span class="verdict-badge ${verdictClass(item.verdict)}">${escapeHtml(formatVerdict(item.verdict))}</span>
                ${item.aiProbability !== null && item.aiProbability !== undefined ?
                    `<span style="font-size: 12px; color: var(--muted);">${(item.aiProbability * 100).toFixed(1)}% (calibration: ${escapeHtml(item.calibrationId || 'unknown')})</span>` : ''}
            </div>
        </div>
    `).join('');

    // Add click handlers
    container.querySelectorAll('.history-item').forEach(el => {
        el.addEventListener('click', () => {
            const index = parseInt(el.dataset.index);
            loadHistoryItem(index);
        });
    });
}

function loadHistoryItem(index) {
    const item = state.history[index];
    if (!item) return;

    // Update input
    elements.textInput.value = item.text;
    updateInputStats();

    // Show results
    handleCompleteAnalysis(item.data, 0);

    // Update active state
    elements.historyList.querySelectorAll('.history-item').forEach((el, i) => {
        el.classList.toggle('active', i === index);
    });
}

// Handle clear
function handleClear() {
    elements.textInput.value = '';
    updateInputStats();
    clearResults();

    if (state.ws) {
        state.ws.close();
        state.ws = null;
    }
}

// Destroy charts
function destroyCharts() {
    if (state.charts.gauge) {
        state.charts.gauge.destroy();
        state.charts.gauge = null;
    }
    if (state.charts.detector) {
        state.charts.detector.destroy();
        state.charts.detector = null;
    }
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Escape a value for safe inclusion in a double-quoted HTML attribute.
// escapeHtml() is text-context only: a browser does not escape quotes
// when serializing a text node, so attribute values need their own
// escaping (IF-05 history sink).
function escapeAttr(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Map a verdict to an allowlisted CSS class fragment. Unknown or
// forged verdicts fall back to "unknown", so imported text can never
// become a class name or markup in the history sink (IF-05).
function verdictClass(verdict) {
    const known = ['ai_like', 'human_like', 'abstain', 'insufficient_evidence', 'mixed'];
    return known.includes(verdict) ? verdict : 'unknown';
}

function formatDate(isoString) {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleString();
}

function formatTime(isoString) {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleTimeString();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (state.ws) {
        state.ws.close();
    }
});

// ────────────────────────────────────────────────────────────────────
// New functionality: Export, Compare, History
// ────────────────────────────────────────────────────────────────────

function exportAnalysis(format) {
    if (!state.currentAnalysis) {
        alert('No analysis to export. Run an analysis first.');
        return;
    }

    const exportData = {
        data: state.currentAnalysis,
        format: format
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `textforensics-report-${Date.now()}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
}

function toggleCompareMode() {
    if (!state.currentAnalysis) {
        alert('No analysis to compare. Run an analysis first.');
        return;
    }

    if (state.secondAnalysis) {
        // Show comparison
        state.compareMode = true;
        renderCompareView();
    } else {
        // Load a history item for comparison
        loadHistoryItemForCompare();
    }
}

function loadHistoryItemForCompare() {
    if (state.history.length === 0) {
        alert('No history items available. Analyze some text first.');
        return;
    }

    const selection = prompt(
        `Select history item (1-${state.history.length}) for comparison:\nLeave empty to cancel.`,
        '1'
    );

    const index = parseInt(selection, 10) - 1;
    if (isNaN(index) || index < 0 || index >= state.history.length) {
        return;
    }

    const item = state.history[index];
    state.secondAnalysis = item.data;
    renderCompareView();
}

function renderCompareView() {
    elements.compareView.classList.remove('hidden');

    const consensusA = state.currentAnalysis?.consensus || {};
    const consensusB = state.secondAnalysis?.consensus || {};

    const verdictLabels = {
        'ai_like': 'AI-like',
        'human_like': 'Human-like',
        'abstain': 'Abstain',
        'insufficient_evidence': 'Insufficient Evidence',
        'mixed': 'Mixed'
    };

    elements.compareASummary.innerHTML = `
        <div class="compare-metric"><strong>Verdict:</strong> ${verdictLabels[consensusA.verdict] || consensusA.verdict}</div>
        <div class="compare-metric"><strong>AI Probability:</strong> ${formatCalibratedProbability(consensusA) ?? 'Not calibrated'}</div>
        <div class="compare-metric"><strong>Families:</strong> ${consensusA.independent_families || 0}</div>
    `;

    elements.compareBSummary.innerHTML = `
        <div class="compare-metric"><strong>Verdict:</strong> ${verdictLabels[consensusB.verdict] || consensusB.verdict}</div>
        <div class="compare-metric"><strong>AI Probability:</strong> ${formatCalibratedProbability(consensusB) ?? 'Not calibrated'}</div>
        <div class="compare-metric"><strong>Families:</strong> ${consensusB.independent_families || 0}</div>
    `;

    renderCompareDetectors();
    renderCompareTrustMap();
    renderCompareVerdict();
}

function renderCompareDetectors() {
    const resultsA = state.currentAnalysis?.detector_results || [];
    const resultsB = state.secondAnalysis?.detector_results || [];
    const mapA = new Map(resultsA.map(d => [d.detector_id, d]));
    const mapB = new Map(resultsB.map(d => [d.detector_id, d]));
    const allIds = [...new Set([...mapA.keys(), ...mapB.keys()])].sort();

    elements.compareDetectors.innerHTML = allIds.map(id => {
        const a = mapA.get(id);
        const b = mapB.get(id);
        // Calibrated probabilities only: a native score must never be
        // rendered as a probability percentage or a pp difference (IF-04).
        const scoreA = a?.calibrated_ai_probability ?? null;
        const scoreB = b?.calibrated_ai_probability ?? null;
        let diff = null;
        if (scoreA !== null && scoreB !== null) {
            diff = ((scoreB - scoreA) * 100).toFixed(1);
        }
        const verdictChanged = a?.verdict !== b?.verdict;

        return `
            <div class="compare-detector-item ${verdictChanged ? 'changed' : ''}">
                <div class="detector-name">${escapeHtml(id)}</div>
                <div class="detector-scores">
                    <span class="score-a">${scoreA !== null ? (scoreA * 100).toFixed(1) + '%' : 'N/A'}</span>
                    <span class="score-diff">${diff !== null ? (diff > 0 ? '↑ ' : '↓ ') + diff + 'pp' : 'N/A'}</span>
                    <span class="score-b">${scoreB !== null ? (scoreB * 100).toFixed(1) + '%' : 'N/A'}</span>
                </div>
                <div class="detector-verdicts">
                    <span class="verdict-badge ${a?.verdict || 'unknown'}">${formatVerdict(a?.verdict || 'unknown')}</span>
                    <span class="verdict-badge ${b?.verdict || 'unknown'}">${formatVerdict(b?.verdict || 'unknown')}</span>
                </div>
            </div>
        `;
    }).join('');
}

function renderCompareTrustMap() {
    const trustA = state.currentAnalysis?.trust_map?.dimensions || [];
    const trustB = state.secondAnalysis?.trust_map?.dimensions || [];
    const mapA = new Map(trustA.map(d => [d.dimension, d]));
    const mapB = new Map(trustB.map(d => [d.dimension, d]));
    const allDims = [...new Set([...mapA.keys(), ...mapB.keys()])].sort();

    elements.compareTrustMap.innerHTML = allDims.map(dim => {
        const a = mapA.get(dim);
        const b = mapB.get(dim);
        const stateChanged = a?.state !== b?.state;

        return `
            <div class="compare-trust-item ${stateChanged ? 'changed' : ''}">
                <div class="trust-name">${escapeHtml(dim.replace(/_/g, ' '))}</div>
                <div class="trust-states">
                    <span class="trust-badge ${a?.state || 'unknown'}">${a?.state || 'N/A'}</span>
                    <span class="trust-badge ${b?.state || 'unknown'}">${b?.state || 'N/A'}</span>
                </div>
            </div>
        `;
    }).join('');
}

function renderCompareVerdict() {
    const consensusA = state.currentAnalysis?.consensus || {};
    const consensusB = state.secondAnalysis?.consensus || {};

    const verdictsMatch = consensusA.verdict === consensusB.verdict;
    const familiesMatch = (consensusA.independent_families || 0) === (consensusB.independent_families || 0);

    elements.compareVerdict.innerHTML = `
        <div class="compare-verdict-diff">
            <div class="verdict-item ${!verdictsMatch ? 'changed' : ''}">
                <span class="label">Verdict Match:</span>
                <span class="value ${!verdictsMatch ? 'changed' : ''}">${verdictsMatch ? 'Yes ✓' : 'No ✗'}</span>
            </div>
            <div class="verdict-item ${!familiesMatch ? 'changed' : ''}">
                <span class="label">Family Count Match:</span>
                <span class="value ${!familiesMatch ? 'changed' : ''}">${familiesMatch ? 'Yes ✓' : 'No ✗'}</span>
            </div>
        </div>
    `;
}

function closeCompareView() {
    state.compareMode = false;
    state.secondAnalysis = null;
    elements.compareView.classList.add('hidden');
}

async function loadServerHistory(filter = {}) {
    try {
        const params = new URLSearchParams();
        if (filter.limit) params.append('limit', filter.limit);
        if (filter.verdict) params.append('verdict', filter.verdict);
        if (filter.family) params.append('family', filter.family);
        if (filter.min_score !== undefined && filter.min_score !== null) params.append('min_score', filter.min_score);
        if (filter.max_score !== undefined && filter.max_score !== null) params.append('max_score', filter.max_score);

        const response = await fetch(`/api/history?${params}`);
        const data = await response.json();
        state.serverHistory = data.entries || [];

        renderServerHistory();
        return data;
    } catch (e) {
        console.error('Failed to load history:', e);
        return [];
    }
}

function renderServerHistory() {
    const container = elements.historyList;

    if (state.serverHistory.length === 0) {
        container.innerHTML = '<div class="history-empty">No server history available.</div>';
        return;
    }

    container.innerHTML = state.serverHistory.map((item, index) => `
        <div class="history-item ${index === 0 ? 'active' : ''}" data-index="${index}" data-id="${escapeAttr(item.id)}">
            <div class="history-preview">
                <div class="history-text">${escapeHtml(item.content_sha256)}</div>
                <div class="history-meta">
                    <span>${escapeHtml(String(item.word_count ?? 0))} words</span>
                    <span>${formatTime(item.stored_at)}</span>
                </div>
            </div>
            <div class="history-verdict">
                <span class="verdict-badge ${verdictClass(item.verdict)}">${escapeHtml(formatVerdict(item.verdict))}</span>
                ${item.calibrated_ai_probability !== null && item.calibrated_ai_probability !== undefined ?
                    `<span style="font-size: 12px; color: var(--muted);">${(item.calibrated_ai_probability * 100).toFixed(1)}%</span>` : ''}
            </div>
        </div>
    `).join('');

    // Add click handlers for history items
    container.querySelectorAll('.history-item').forEach(el => {
        el.addEventListener('click', () => {
            const historyId = el.dataset.id;
            loadHistoryItemById(historyId);
        });
    });
}

async function loadHistoryItemById(historyId) {
    try {
        const response = await fetch(`/api/history/${historyId}`);
        if (!response.ok) {
            alert('History item not found.');
            return;
        }
        const data = await response.json();
        state.currentAnalysis = data.data;
        handleCompleteAnalysis(data.data, 0);

        // Update active state in history list
        elements.historyList.querySelectorAll('.history-item').forEach(el => {
            el.classList.toggle('active', el.dataset.id === historyId);
        });
    } catch (e) {
        alert('Failed to load history item: ' + e.message);
    }
}
