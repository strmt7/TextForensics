/**
 * TextForensics Web UI - Real-time Analysis & Visualization
 */

// State management
const state = {
    history: [],
    currentAnalysis: null,
    ws: null,
    isStreaming: true,
    charts: {
        gauge: null,
        detector: null
    }
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
    btnLoader: document.querySelector('.btn-loader')
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

// Update top metrics
function updateMetrics(data, elapsedMs) {
    const consensus = data.consensus;
    const trustMap = data.trust_map;

    // Consensus verdict
    elements.consensusVerdict.textContent = formatVerdict(consensus.verdict);
    elements.consensusVerdict.className = `metric-value verdict-${consensus.verdict}`;

    if (consensus.ai_probability !== null && consensus.ai_probability !== undefined) {
        elements.consensusConfidence.textContent = `AI Probability: ${(consensus.ai_probability * 100).toFixed(1)}%`;
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

    // Determine AI probability
    let aiProb = 0;
    if (data.consensus.ai_probability !== null && data.consensus.ai_probability !== undefined) {
        aiProb = data.consensus.ai_probability * 100;
    } else if (data.consensus.verdict === 'ai_like') {
        aiProb = 85;
    } else if (data.consensus.verdict === 'human_like') {
        aiProb = 15;
    } else {
        aiProb = 50;
    }

    // Destroy existing chart
    if (state.charts.gauge) {
        state.charts.gauge.destroy();
    }

    state.charts.gauge = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [aiProb, 100 - aiProb],
                backgroundColor: [
                    getGaugeColor(aiProb),
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
        ctx.fillText(`${aiProb.toFixed(0)}%`, centerX, centerY);

        ctx.font = '12px system-ui';
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted').trim() || '#9aa4af';
        ctx.fillText('AI Probability', centerX, centerY + 30);
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

    // Prepare data from family votes
    const families = consensus.family_votes || [];
    const labels = families.map(f => f.detector_family.replace(/-/g, ' '));
    const scores = families.map(f => f.calibrated_ai_probability !== null ? f.calibrated_ai_probability * 100 : 50);
    const colors = scores.map(s => getGaugeColor(s));

    if (state.charts.detector) {
        state.charts.detector.destroy();
    }

    state.charts.detector = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'AI Probability %',
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
                        label: (ctx) => `${ctx.dataset.label}: ${ctx.raw.toFixed(1)}%`
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
            // Normalize score for display (assuming 0-1 range)
            const normalized = Math.max(0, Math.min(1, score));
            displayScore = `${(normalized * 100).toFixed(1)}%`;
            scorePercent = normalized * 100;
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
                <span class="verdict-value">${consensus.ai_probability !== null ? (consensus.ai_probability * 100).toFixed(1) + '%' : 'Not calibrated'}</span>
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
    const historyItem = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        text: elements.textInput.value.trim(),
        preview: elements.textInput.value.trim().substring(0, 100) + (elements.textInput.value.length > 100 ? '…' : ''),
        verdict: data.consensus.verdict,
        aiProbability: data.consensus.ai_probability,
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
                    <span>${item.wordCount} words</span>
                    <span>${formatTime(item.timestamp)}</span>
                </div>
            </div>
            <div class="history-verdict">
                <span class="verdict-badge ${item.verdict}">${formatVerdict(item.verdict)}</span>
                ${item.aiProbability !== null && item.aiProbability !== undefined ?
                    `<span style="font-size: 12px; color: var(--muted);">${(item.aiProbability * 100).toFixed(0)}%</span>` : ''}
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
