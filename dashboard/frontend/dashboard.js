// AI Cyber Shield Dashboard - JavaScript Handler
let socket;
let trafficChart;
const maxChartPoints = 15;
let chartLabels = [];
let chartRxData = [];
let chartTxData = [];

// Popup modal tracking states
let lastSeenAttackType = null;
let modalDismissedForAttack = false;

// Voice alert state triggers
let wasThreatActive = false;
let wasPreventionFailed = false;
let wasIsolationActive = false;

// Custom toast notification & persistent audit logs
let notifiedProcessActions = new Set();
let persistentFrontendEvents = [];
let didCurrentAttackCycleFail = false;
let isFirstTick = true;
let lastAnnouncementId = null;


// Initialize Telemetry Chart
function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [
                {
                    label: 'Rx Traffic (KB/s)',
                    data: chartRxData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2
                },
                {
                    label: 'Tx Traffic (KB/s)',
                    data: chartTxData,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#f3f4f6' }
                }
            }
        }
    });
}

function updateChart(rxRate, txRate) {
    const timeStr = new Date().toLocaleTimeString();
    
    chartLabels.push(timeStr);
    chartRxData.push((rxRate / 1024).toFixed(1)); // Convert to KB/s
    chartTxData.push((txRate / 1024).toFixed(1)); // Convert to KB/s
    
    if (chartLabels.length > maxChartPoints) {
        chartLabels.shift();
        chartRxData.shift();
        chartTxData.shift();
    }
    
    trafficChart.update();
}

// Connect WebSocket
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    socket = new WebSocket(wsUrl);
    
    socket.onopen = () => {
        console.log("WebSocket connected successfully.");
        document.getElementById("system-status").innerHTML = '<div class="status-dot" style="background-color: #3b82f6; box-shadow: 0 0 10px #3b82f6;"></div> CONNECTED';
        document.getElementById("system-status").style.color = "#3b82f6";
        document.getElementById("system-status").style.borderColor = "rgba(59, 130, 246, 0.3)";
        showToast("Shield connected", "Awaiting Microsoft Account Authentication.", "info");
        addPersistentFrontendEvent("info", "[AI Shield] Command console connected. Awaiting Microsoft Account sign-in.");
    };

    
    socket.onclose = () => {
        console.warn("WebSocket disconnected. Retrying in 3 seconds...");
        document.getElementById("system-status").innerHTML = '<div class="status-dot" style="background-color: var(--danger); box-shadow: 0 0 10px var(--danger);"></div> CONNECTION LOST';
        document.getElementById("system-status").style.color = "var(--danger)";
        document.getElementById("system-status").style.borderColor = "rgba(239, 68, 68, 0.3)";
        setTimeout(connectWebSocket, 3000);
    };
    
    socket.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        handleTelemetry(payload);
    };
}

// Handle incoming telemetry stream
function handleTelemetry(data) {
    // Validate authentication state
    if (data.auth) {
        const authPanel = document.getElementById("auth-modal-overlay");
        const accountInfo = document.getElementById("account-info-container");
        if (data.auth.authenticated) {
            authPanel.style.display = "none";
            accountInfo.style.display = "flex";
            document.getElementById("account-name").innerText = data.auth.user_profile.name;
            document.getElementById("account-email").innerText = `🛡️ Account Protected (${data.auth.user_profile.email})`;
            
            const initials = data.auth.user_profile.name.split(" ").map(n => n[0]).join("").substring(0, 2).toUpperCase();
            document.getElementById("account-avatar").innerText = initials;
        } else {
            authPanel.style.display = "flex";
            accountInfo.style.display = "none";
            
            document.getElementById("system-status").innerHTML = '<div class="status-dot" style="background-color: var(--warning); box-shadow: 0 0 10px var(--warning);"></div> STANDBY (UNAUTHENTICATED)';
            document.getElementById("system-status").style.color = "var(--warning)";
            document.getElementById("system-status").style.borderColor = "rgba(245, 158, 11, 0.3)";
            return; // Freeze interface updates when not authenticated
        }
    }

    // Check for initial load tick to prevent false alert triggers on refresh
    if (isFirstTick) {
        isFirstTick = false;
        wasThreatActive = data.threat.is_threat;
        wasPreventionFailed = data.protection && data.protection.prevention_failed;
        wasIsolationActive = data.protection && data.protection.isolation && data.protection.isolation.is_active;
        lastSeenAttackType = data.threat.is_threat ? data.threat.attack_type : "None";
        didCurrentAttackCycleFail = wasPreventionFailed;
        lastAnnouncementId = data.announcement ? data.announcement.id : 0;

        
        // Initialize process actions set to avoid duplicate notifications on load
        const actions = (data.protection && data.protection.active_protocol && data.protection.active_protocol.actions) || [];
        actions.forEach(action => {
            if (action.type === "process" && action.message.includes("Virus removed successfully")) {
                notifiedProcessActions.add(action.message);
            }
        });
        
        // Render initial UI values
        document.getElementById("val-connections").innerText = data.network.connection_count;
        const totalTraffic = (data.network.bytes_sent_rate + data.network.bytes_recv_rate) / 1024;
        document.getElementById("val-traffic").innerText = `${totalTraffic.toFixed(1)} KB/s`;
        document.getElementById("val-file-rate").innerText = `${data.file.modification_rate} / min`;
        
        const fileTrend = document.getElementById("val-file-status");
        if (data.file.modification_rate > 100) {
            fileTrend.innerText = "ALERT Extreme Activity";
            fileTrend.style.color = "var(--danger)";
        } else if (data.file.modification_rate > 20) {
            fileTrend.innerText = "WARN High Activity";
            fileTrend.style.color = "var(--warning)";
        } else {
            fileTrend.innerText = "OK Idle State";
            fileTrend.style.color = "var(--success)";
        }
        
        const anomalyPercent = data.anomaly.anomaly_score;
        document.getElementById("val-anomaly").innerText = `${anomalyPercent.toFixed(1)}%`;
        const anomalyTrend = document.getElementById("val-anomaly-status");
        if (data.anomaly.is_anomaly) {
            anomalyTrend.innerText = "ALERT Anomaly flag set";
            anomalyTrend.style.color = "var(--danger)";
        } else {
            anomalyTrend.innerText = "OK Safe baseline";
            anomalyTrend.style.color = "var(--success)";
        }
        
        updateProtectionPanel(data.protection);
        updateFirewallPanel(data.protection ? data.protection.firewall : null);
        updateChart(data.network.bytes_recv_rate, data.network.bytes_sent_rate);
        
        // Build initial logs
        const logList = document.getElementById("audit-logs");
        if (logList) {
            logList.innerHTML = "";
            const mergedAuditLogs = [];
            
            // Add initial active classification if threat is active
            if (data.threat.is_threat) {
                mergedAuditLogs.push({
                    type: "threat",
                    timestamp: new Date().toLocaleTimeString(),
                    message: `[AI Threat Classifier] CLASSIFIED THREAT: ${data.threat.attack_type} (Confidence: ${(data.threat.confidence * 100).toFixed(0)}%)`
                });
            }
            
            data.file.event_history.slice(0, 8).forEach(evt => {
                mergedAuditLogs.push({
                    type: "file",
                    timestamp: evt.timestamp,
                    message: `[File System] ${evt.type}: ${evt.filename}`
                });
            });
            
            data.log.suspicious_entries.slice(0, 10).forEach(ent => {
                mergedAuditLogs.push({
                    type: "log",
                    timestamp: ent.timestamp,
                    message: `[Audit Log] ${ent.message}`
                });
            });
            
            mergedAuditLogs.forEach(log => {
                const div = document.createElement("div");
                div.className = `log-item ${log.type === 'threat' ? 'threat' : ''}`;
                div.innerHTML = `
                    <span class="log-timestamp">${log.timestamp}</span>
                    <span class="log-msg">${log.message}</span>
                `;
                logList.appendChild(div);
            });
        }
        return;
    }

    // 1. Update Core Metric Widgets
    document.getElementById("val-connections").innerText = data.network.connection_count;
    
    const totalTraffic = (data.network.bytes_sent_rate + data.network.bytes_recv_rate) / 1024;
    document.getElementById("val-traffic").innerText = `${totalTraffic.toFixed(1)} KB/s`;
    
    document.getElementById("val-file-rate").innerText = `${data.file.modification_rate} / min`;
    
    // File rate status colors
    const fileTrend = document.getElementById("val-file-status");
    if (data.file.modification_rate > 100) {
        fileTrend.innerText = "ALERT Extreme Activity";
        fileTrend.style.color = "var(--danger)";
    } else if (data.file.modification_rate > 20) {
        fileTrend.innerText = "WARN High Activity";
        fileTrend.style.color = "var(--warning)";
    } else {
        fileTrend.innerText = "OK Idle State";
        fileTrend.style.color = "var(--success)";
    }
    
    // Anomaly values
    const anomalyPercent = data.anomaly.anomaly_score;
    document.getElementById("val-anomaly").innerText = `${anomalyPercent.toFixed(1)}%`;
    const anomalyTrend = document.getElementById("val-anomaly-status");
    if (data.anomaly.is_anomaly) {
        anomalyTrend.innerText = "ALERT Anomaly flag set";
        anomalyTrend.style.color = "var(--danger)";
    } else {
        anomalyTrend.innerText = "OK Safe baseline";
        anomalyTrend.style.color = "var(--success)";
    }
    
    updateProtectionPanel(data.protection);
    updateFirewallPanel(data.protection ? data.protection.firewall : null);

    // Update live graph
    updateChart(data.network.bytes_recv_rate, data.network.bytes_sent_rate);
    
    // 2. Alert Banner handler
    const alertBanner = document.getElementById("threat-alert");
    const viewDefenseBtn = document.getElementById("btn-view-defense");
    if (data.threat.is_threat) {
        document.getElementById("alert-type").innerText = `CRITICAL THREAT DETECTED: ${data.threat.attack_type}`;
        document.getElementById("alert-details").innerText = `Machine Learning Model matched threat type. Confidence: ${(data.threat.confidence * 100).toFixed(0)}%. Severity: ${data.threat.severity_score}/100.`;
        alertBanner.style.display = "flex";
        if (viewDefenseBtn) {
            viewDefenseBtn.style.display = "inline-block";
        }

        // Update popup modal data dynamically
        const currentAttack = data.threat.attack_type;
        const modalThreatType = document.getElementById("modal-threat-type");
        const modalConfidence = document.getElementById("modal-confidence");
        const modalDefenseMode = document.getElementById("modal-defense-mode");
        const modalOpsList = document.getElementById("modal-operations-list");

        if (modalThreatType) modalThreatType.innerText = currentAttack;
        if (modalConfidence) modalConfidence.innerText = `${(data.threat.confidence * 100).toFixed(0)}% (Severity: ${data.threat.severity_score}/100)`;
        
        const mode = (data.protection && data.protection.active_protocol && data.protection.active_protocol.mode) || "monitoring";
        if (modalDefenseMode) {
            modalDefenseMode.innerText = mode.replace(/_/g, " ").toUpperCase();
        }

        if (modalOpsList) {
            modalOpsList.innerHTML = "";
            const actions = (data.protection && data.protection.active_protocol && data.protection.active_protocol.actions) || [];
            if (actions.length === 0) {
                modalOpsList.innerHTML = `
                    <div class="operation-item">
                        <div class="op-status status-ready">WAITING</div>
                        <div class="op-desc">Analyzing threat signatures & mapping response...</div>
                    </div>
                `;
            } else {
                actions.forEach(action => {
                    const item = document.createElement("div");
                    item.className = "operation-item";
                    
                    let statusClass = "status-ready";
                    let statusText = "INITIATING";
                    if (action.status === "simulated" || action.status === "active") {
                        statusClass = "status-success";
                        statusText = "EXECUTED";
                    } else if (action.status === "disabled") {
                        statusClass = "status-bypass";
                        statusText = "BYPASSED";
                    } else if (action.status === "failed") {
                        statusClass = "status-failed";
                        statusText = "FAILED";
                    }
                    
                    item.innerHTML = `
                        <div class="op-status ${statusClass}">${statusText}</div>
                        <div class="op-desc">${action.message}</div>
                    `;
                    modalOpsList.appendChild(item);
                });
            }
        }

        // Check for process-based virus removal action
        const actions = (data.protection && data.protection.active_protocol && data.protection.active_protocol.actions) || [];
        actions.forEach(action => {
            if (action.type === "process" && (action.status === "active" || action.status === "simulated") && action.message.includes("Virus removed successfully")) {
                if (!notifiedProcessActions.has(action.message)) {
                    notifiedProcessActions.add(action.message);
                    showToast("Virus removed successfully", action.message, "success");
                    addPersistentFrontendEvent("threat", `[AI Shield] Virus removed successfully: Suspect process terminated.`);
                }
            }
        });

        // Auto-popup modal trigger on initial threat classification
        const preventionFailed = data.protection && data.protection.prevention_failed;
        const isolationActive = data.protection && data.protection.isolation && data.protection.isolation.is_active;
        
        if (currentAttack !== lastSeenAttackType) {
            lastSeenAttackType = currentAttack;
            modalDismissedForAttack = false;
            didCurrentAttackCycleFail = false;
            showDefenseModal();
            showToast("We are under attack", "Protection mode activated.", "warning");
            addPersistentFrontendEvent("threat", `[AI Shield] We are under attack and protection mode activated.`);
        }
        
        if (preventionFailed) {
            didCurrentAttackCycleFail = true;
        }

        if (preventionFailed && !wasPreventionFailed) {
            showToast("Protection fails", "Active threat bypassed security shields. Fail-safe isolation initiated.", "danger");
            addPersistentFrontendEvent("threat", "[AI Shield] Protection fails: Malware bypassed prevention layer.");
        }
        
        if (isolationActive && !wasIsolationActive) {
            const isRansomware = currentAttack && currentAttack.toLowerCase().includes("ransomware");
            if (preventionFailed || isRansomware) {
                showToast("Sensitive data protected successfully", "All critical documents and user files secured in the isolation vault.", "success");
                addPersistentFrontendEvent("threat", "[AI Shield] Sensitive data protected successfully: Files secured in isolation vault.");
            }
        }
        
        wasThreatActive = true;
        wasPreventionFailed = preventionFailed;
        wasIsolationActive = isolationActive;
    } else {
        if (viewDefenseBtn) {
            viewDefenseBtn.style.display = "none";
        }
        // Only hide if not simulated sticky alert
        if (!data.threat.simulated_attack) {
            alertBanner.style.display = "none";
        }
        
        // Resolve alert speech trigger
        if (wasThreatActive) {
            if (didCurrentAttackCycleFail) {
                showToast("System breached", "Attack cleared, but prevention layer failed.", "danger");
                addPersistentFrontendEvent("threat", "[AI Shield] System breached: Protection failed and system fallback triggered.");
            } else {
                showToast("Successfully protected", "Threat mitigated and security shields are holding.", "success");
                addPersistentFrontendEvent("threat", "[AI Shield] Successfully protected: Threat mitigated, system security restored.");
            }
            notifiedProcessActions.clear();
            didCurrentAttackCycleFail = false;
        }
        wasThreatActive = false;
        wasPreventionFailed = false;
        wasIsolationActive = false;

        // Reset tracking states and close popup when threat cleared
        if (lastSeenAttackType !== null) {
            lastSeenAttackType = null;
            modalDismissedForAttack = false;
            closeDefenseModal();
        }
    }

    // Unified voice announcement system from backend state
    if (data.announcement && data.announcement.id > lastAnnouncementId) {
        lastAnnouncementId = data.announcement.id;
        if (data.announcement.text) {
            speakMessage(data.announcement.text);
        }
    }
    
    // 3. Process Table list
    const procTbody = document.getElementById("process-list");
    procTbody.innerHTML = "";
    data.process.top_processes.forEach(proc => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${proc.pid}</td>
            <td style="font-weight: 600;">${proc.name}</td>
            <td style="color: ${proc.cpu_percent > 50 ? 'var(--danger)' : 'var(--text-primary)'};">${proc.cpu_percent}%</td>
            <td style="color: ${proc.memory_percent > 30 ? 'var(--warning)' : 'var(--text-primary)'};">${proc.memory_percent}%</td>
        `;
        procTbody.appendChild(row);
    });
    
    // 4. Update Audit logs
    const logList = document.getElementById("audit-logs");
    logList.innerHTML = "";
    
    // Render suspicious file events, high logins, threat logs
    const mergedAuditLogs = [];

    // Prepend persistent notification events
    persistentFrontendEvents.forEach(evt => {
        mergedAuditLogs.push(evt);
    });
    
    // Add threat predictions
    if (data.threat.is_threat) {
        mergedAuditLogs.push({
            type: "threat",
            timestamp: new Date().toLocaleTimeString(),
            message: `[AI Threat Classifier] CLASSIFIED THREAT: ${data.threat.attack_type} (Confidence: ${(data.threat.confidence * 100).toFixed(0)}%)`
        });
    }
    if (data.anomaly.is_anomaly) {
        mergedAuditLogs.push({
            type: "threat",
            timestamp: new Date().toLocaleTimeString(),
            message: `[AI Anomaly Detector] CPU/RAM/process allocation anomaly identified (Score: ${data.anomaly.anomaly_score}%)`
        });
    }
    
    // Add file monitor notifications
    data.file.event_history.slice(0, 8).forEach(evt => {
        mergedAuditLogs.push({
            type: "file",
            timestamp: evt.timestamp,
            message: `[File System] ${evt.type}: ${evt.filename}`
        });
    });
    
    // Add scanned log entries
    data.log.suspicious_entries.slice(0, 10).forEach(ent => {
        mergedAuditLogs.push({
            type: "log",
            timestamp: ent.timestamp,
            message: `[Audit Log] ${ent.message}`
        });
    });
    
    // Sort combined events
    mergedAuditLogs.forEach(log => {
        const div = document.createElement("div");
        div.className = `log-item ${log.type === 'threat' ? 'threat' : ''}`;
        div.innerHTML = `
            <span class="log-timestamp">${log.timestamp}</span>
            <span class="log-msg">${log.message}</span>
        `;
        logList.appendChild(div);
    });
    
    if (mergedAuditLogs.length === 0) {
        logList.innerHTML = '<div class="log-item"><span class="log-timestamp">INFO</span><span class="log-msg">Scanning channels active... No anomalies identified.</span></div>';
    }
}

function updateProtectionPanel(protection) {
    if (!protection) return;

    const forecast = protection.forecast || {};
    const backup = protection.backup || {};
    const snapshot = backup.last_snapshot || {};
    const protocol = protection.active_protocol || {};
    const level = forecast.level || "normal";
    const isolation = protection.isolation || {};
    const preventionFailed = protection.prevention_failed || false;

    // Update switch toggle in UI from backend state
    const failToggle = document.getElementById("toggle-failure");
    if (failToggle && failToggle !== document.activeElement) {
        failToggle.checked = preventionFailed;
    }

    document.getElementById("val-protection-risk").innerText = `${(forecast.risk_score || 0).toFixed(1)}%`;

    const levelEl = document.getElementById("val-protection-level");
    levelEl.innerText = `${level.toUpperCase()} - ${forecast.recommended_action || "Continue monitoring baseline."}`;
    levelEl.style.color = level === "critical" ? "var(--danger)" : level === "warning" ? "var(--warning)" : "var(--success)";

    document.getElementById("val-snapshot-count").innerText = `${snapshot.file_count || 0} files`;
    const lastAction = protection.last_action || {};
    document.getElementById("val-snapshot-status").innerText = snapshot.created_at
        ? `${snapshot.status} at ${snapshot.created_at}. ${snapshot.message || lastAction.message || ""}`
        : "Waiting for risk signal";

    const mode = protocol.mode || "monitoring";
    const modeEl = document.getElementById("val-protection-mode");
    modeEl.innerText = mode.replace(/_/g, " ").toUpperCase();
    modeEl.style.color = mode === "containment" || mode === "isolation" ? "var(--danger)" : mode === "early_guard" || mode === "prevention" ? "var(--warning)" : "var(--success)";
    document.getElementById("val-protection-action").innerText = lastAction.message || "No guard action active";

    const signalList = document.getElementById("protection-signals");
    signalList.innerHTML = "";
    const signals = forecast.signals || [];
    if (signals.length === 0) {
        signalList.innerHTML = '<div class="signal-item">No elevated signals</div>';
    } else {
        signals.slice(0, 5).forEach(signal => {
            const div = document.createElement("div");
            div.className = "signal-item";
            div.innerText = signal;
            signalList.appendChild(div);
        });
    }

    const actionList = document.getElementById("protection-actions");
    actionList.innerHTML = "";
    const actions = protocol.actions || [];
    if (actions.length === 0) {
        actionList.innerHTML = '<div class="signal-item">No protection actions yet</div>';
    } else {
        actions.slice(0, 5).forEach(action => {
            const div = document.createElement("div");
            div.className = "signal-item";
            div.innerText = `[${(action.status || "ready").toUpperCase()}] ${action.message}`;
            actionList.appendChild(div);
        });
    }

    // Vault Details Manifest UI render
    const vaultPanel = document.getElementById("vault-details");
    const vaultFiles = document.getElementById("vault-files");
    
    if (vaultPanel && vaultFiles) {
        if (isolation.is_active && isolation.isolated_files && isolation.isolated_files.length > 0) {
            vaultPanel.style.display = "block";
            vaultFiles.innerHTML = "";
            isolation.isolated_files.forEach(file => {
                const div = document.createElement("div");
                div.className = "vault-file-item";
                
                const sizeKB = (file.bytes / 1024).toFixed(2);
                div.innerHTML = `
                    <span class="vault-file-name">🔒 ${file.filename}.isolated</span>
                    <span class="vault-file-meta">Moved: ${file.original_path.substring(Math.max(file.original_path.lastIndexOf('\\'), file.original_path.lastIndexOf('/')) + 1)} (${sizeKB} KB)</span>
                `;
                vaultFiles.appendChild(div);
            });
        } else {
            vaultPanel.style.display = "none";
            vaultFiles.innerHTML = "";
        }
    }
}

// Dismiss simulated threat display manually
function dismissAlert() {
    document.getElementById("threat-alert").style.display = "none";
    setSim('None');
}

// Call threat simulator endpoint
function setSim(attackType) {
    // Highlight correct simulation selector button
    const buttons = document.querySelectorAll(".simulator-grid button");
    buttons.forEach(btn => btn.classList.remove("btn-active"));
    
    const activeBtnId = `sim-${attackType.replace(/\s+/g, '-')}`;
    const activeBtn = document.getElementById(activeBtnId);
    if (activeBtn) activeBtn.classList.add("btn-active");
    
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
            action: "trigger_simulation",
            attack_type: attackType
        }));
        return;
    }

    fetch(`/api/simulate/${encodeURIComponent(attackType)}`, { method: "POST" })
        .then(response => response.json())
        .then(() => fetch("/api/status"))
        .then(response => response.json())
        .then(handleTelemetry)
        .catch(error => console.error("Simulation trigger failed:", error));
}

// Toggle simulated prevention failure state
function toggleFailureState() {
    const isChecked = document.getElementById("toggle-failure").checked;
    
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
            action: "toggle_prevention_failure",
            failed: isChecked
        }));
        return;
    }

    fetch(`/api/simulate/failure/${isChecked}`, { method: "POST" })
        .then(response => response.json())
        .then(() => fetch("/api/status"))
        .then(response => response.json())
        .then(handleTelemetry)
        .catch(error => console.error("Failed to toggle prevention failure:", error));
}

// Active Defense Popup Modal display controllers
function showDefenseModal() {
    const modal = document.getElementById("defense-modal-overlay");
    if (modal) {
        modal.style.display = "flex";
        setTimeout(() => {
            modal.style.opacity = "1";
        }, 10);
    }
}

function closeDefenseModal() {
    const modal = document.getElementById("defense-modal-overlay");
    if (modal) {
        modal.style.opacity = "0";
        setTimeout(() => {
            modal.style.display = "none";
        }, 300);
    }
    modalDismissedForAttack = true;
}

// Audio announcement alert utilizing Web Speech API with Female Voice support
function speakMessage(text) {
    if ('speechSynthesis' in window) {
        // Cancel ongoing speech to ensure the alert is spoken immediately
        window.speechSynthesis.cancel();
        
        const utterance = new SpeechSynthesisUtterance(text);
        
        // Find a female voice from the available voices list
        const voices = window.speechSynthesis.getVoices();
        let femaleVoice = voices.find(voice => {
            const name = voice.name.toLowerCase();
            return name.includes("female") || 
                   name.includes("zira") || 
                   name.includes("samantha") || 
                   name.includes("hazel") ||
                   name.includes("google us english") ||
                   name.includes("victoria") ||
                   name.includes("karen") ||
                   name.includes("natural") ||
                   name.includes("salli") ||
                   name.includes("joanna");
        });
        
        // Fallback to select a non-male voice if typical female profiles aren't found
        if (!femaleVoice) {
            femaleVoice = voices.find(voice => {
                const name = voice.name.toLowerCase();
                return !name.includes("david") && 
                       !name.includes("george") && 
                       !name.includes("ravi") && 
                       !name.includes("mark") && 
                       !name.includes("male");
            });
        }
        
        if (femaleVoice) {
            utterance.voice = femaleVoice;
        }
        
        utterance.rate = 1.0;
        utterance.pitch = 1.05; // Slightly higher pitch for female serious warning tone
        
        window.speechSynthesis.speak(utterance);
    } else {
        console.warn("Audio Alert: Speech synthesis not supported in this browser environment.");
    }
}

window.onload = () => {
    initChart();
    connectWebSocket();
};

// Premium Toast Notification System
function showToast(title, message, type = 'info') {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;

    // Select icon based on toast type
    let iconSvg = '';
    if (type === 'success') {
        iconSvg = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
    } else if (type === 'danger') {
        iconSvg = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
    } else if (type === 'warning') {
        iconSvg = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    } else {
        iconSvg = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
    }

    toast.innerHTML = `
        <div class="toast-icon">${iconSvg}</div>
        <div class="toast-info-box">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <div class="toast-close" onclick="this.parentElement.classList.remove('show'); setTimeout(() => this.parentElement.remove(), 400);">&times;</div>
    `;

    container.appendChild(toast);

    // Trigger reflow for transition
    toast.offsetHeight;

    // Show toast
    toast.classList.add("show");

    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.classList.remove("show");
            setTimeout(() => toast.remove(), 400);
        }
    }, 5000);
}

// Add persistent notifications to live logs
function addPersistentFrontendEvent(type, message) {
    persistentFrontendEvents.unshift({
        type: type,
        timestamp: new Date().toLocaleTimeString(),
        message: message
    });
    // Keep max 20 events
    persistentFrontendEvents = persistentFrontendEvents.slice(0, 20);
}

// Update 5-Layer Firewall Active Rules Panel
function updateFirewallPanel(firewall) {
    if (!firewall) return;

    // L1: Network IP Filter
    const ipsCount = firewall.blocked_ips.length;
    const ipsBadge = document.getElementById("fw-ips-blocked");
    const ipsList = document.getElementById("fw-ips-list");
    const cardIp = document.getElementById("layer-ip");
    
    if (ipsBadge && ipsList && cardIp) {
        ipsBadge.innerText = `${ipsCount} blocked IP${ipsCount === 1 ? '' : 's'}`;
        if (ipsCount > 0) {
            ipsList.innerText = firewall.blocked_ips.join(", ");
            cardIp.classList.add("violation");
        } else {
            ipsList.innerText = "No IPs blocked";
            cardIp.classList.remove("violation");
        }
    }

    // L2: Transport Port Guard
    const portsCount = firewall.blocked_ports.length;
    const portsBadge = document.getElementById("fw-ports-blocked");
    const portsList = document.getElementById("fw-ports-list");
    const cardPort = document.getElementById("layer-port");
    
    if (portsBadge && portsList && cardPort) {
        portsBadge.innerText = `${portsCount} blocked port${portsCount === 1 ? '' : 's'}`;
        if (portsCount > 0) {
            portsList.innerText = firewall.blocked_ports.map(p => `Port ${p}`).join(", ");
            cardPort.classList.add("violation");
        } else {
            portsList.innerText = "No ports blocked";
            cardPort.classList.remove("violation");
        }
    }

    // L3: Application Inspector
    const scannedPayloads = firewall.payloads_scanned;
    const appBadge = document.getElementById("fw-payloads-scanned");
    const appStatus = document.getElementById("fw-payloads-status");
    const cardApp = document.getElementById("layer-app");
    
    if (appBadge && appStatus && cardApp) {
        appBadge.innerText = `${scannedPayloads} payload${scannedPayloads === 1 ? '' : 's'} scanned`;
        if (firewall.violations_detected > 0) {
            appStatus.innerText = `${firewall.violations_detected} signature anomalies`;
            cardApp.classList.add("violation");
        } else {
            appStatus.innerText = "No anomalies detected";
            cardApp.classList.remove("violation");
        }
    }

    // L4: Process Binding Guard
    const verifiedProcs = firewall.processes_verified;
    const processBadge = document.getElementById("fw-processes-verified");
    const processStatus = document.getElementById("fw-processes-status");
    
    if (processBadge && processStatus) {
        processBadge.innerText = `${verifiedProcs} process${verifiedProcs === 1 ? '' : 'es'} verified`;
        processStatus.innerText = "All bindings safe";
    }

    // L5: Behavioral Rate Limiter
    const rateViolations = firewall.rate_limit_violations;
    const behavioralBadge = document.getElementById("fw-rate-violations");
    const behavioralStatus = document.getElementById("fw-rate-status");
    const cardBehavioral = document.getElementById("layer-behavioral");
    
    if (behavioralBadge && behavioralStatus && cardBehavioral) {
        behavioralBadge.innerText = `${rateViolations} rate violation${rateViolations === 1 ? '' : 's'}`;
        if (rateViolations > 0) {
            behavioralStatus.innerText = "DDoS Flooding Throttled";
            cardBehavioral.classList.add("violation");
        } else {
            behavioralStatus.innerText = "Traffic within baseline";
            cardBehavioral.classList.remove("violation");
        }
    }
}

// Authentication UI and API integration
let currentAuthMethod = 'demo';
let activeUserCode = null;
let pollInterval = null;

function setAuthMethod(method) {
    currentAuthMethod = method;
    const btnDemo = document.getElementById("btn-method-demo");
    const btnReal = document.getElementById("btn-method-real");
    const btnPass = document.getElementById("btn-method-pass");
    const demoForm = document.getElementById("auth-demo-form");
    const realForm = document.getElementById("auth-real-form");
    const passForm = document.getElementById("auth-pass-form");
    
    // Reset borders & buttons
    btnDemo.classList.remove("btn-active");
    btnDemo.style.borderColor = "rgba(255,255,255,0.08)";
    btnReal.classList.remove("btn-active");
    btnReal.style.borderColor = "rgba(255,255,255,0.08)";
    btnPass.classList.remove("btn-active");
    btnPass.style.borderColor = "rgba(255,255,255,0.08)";
    
    demoForm.style.display = "none";
    realForm.style.display = "none";
    passForm.style.display = "none";
    
    if (method === 'demo') {
        btnDemo.classList.add("btn-active");
        btnDemo.style.borderColor = "var(--primary)";
        demoForm.style.display = "block";
    } else if (method === 'real') {
        btnReal.classList.add("btn-active");
        btnReal.style.borderColor = "var(--primary)";
        realForm.style.display = "block";
    } else if (method === 'pass') {
        btnPass.classList.add("btn-active");
        btnPass.style.borderColor = "var(--primary)";
        passForm.style.display = "block";
    }
    hideAuthError();
}

function showAuthError(msg) {
    const errorEl = document.getElementById("auth-error-message");
    errorEl.innerText = msg;
    errorEl.style.display = "block";
}

function hideAuthError() {
    document.getElementById("auth-error-message").style.display = "none";
}

function submitDemoLogin() {
    const email = document.getElementById("auth-email").value.trim();
    const name = document.getElementById("auth-name").value.trim();
    
    if (!email || !email.includes("@")) {
        showAuthError("Please enter a valid Microsoft account email address.");
        return;
    }
    if (!name) {
        showAuthError("Please enter a display name.");
        return;
    }
    
    hideAuthError();
    
    fetch("/api/auth/demo-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, name: name })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            showToast("Authenticated successfully", `System protection active for ${data.user_info.name}`, "success");
        } else {
            showAuthError(data.message || "Failed to log in.");
        }
    })
    .catch(err => {
        console.error("Demo login error:", err);
        showAuthError("Network error. Make sure backend is running.");
    });
}

function startMsalDeviceFlow() {
    hideAuthError();
    const btnGen = document.getElementById("btn-generate-code");
    btnGen.innerText = "Generating Code...";
    btnGen.disabled = true;
    
    fetch("/api/auth/device-flow", { method: "POST" })
    .then(res => res.json())
    .then(data => {
        btnGen.innerText = "Generate Login Code";
        btnGen.disabled = false;
        
        if (data.status === "success") {
            activeUserCode = data.user_code;
            document.getElementById("auth-device-code").innerText = data.user_code;
            document.getElementById("auth-code-display-panel").style.display = "block";
            
            // Start polling MSAL status
            startMsalPolling(data.user_code);
        } else {
            showAuthError(data.message || "Failed to start MSAL flow.");
        }
    })
    .catch(err => {
        btnGen.innerText = "Generate Login Code";
        btnGen.disabled = false;
        console.error("Device flow error:", err);
        showAuthError("MSAL generation error. Check if library is installed.");
    });
}

function startMsalPolling(userCode) {
    if (pollInterval) clearInterval(pollInterval);
    
    // Poll every 5 seconds
    pollInterval = setInterval(() => {
        if (!activeUserCode || activeUserCode !== userCode) {
            clearInterval(pollInterval);
            return;
        }
        
        fetch(`/api/auth/poll/${userCode}`, { method: "POST" })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                clearInterval(pollInterval);
                activeUserCode = null;
                showToast("Microsoft login complete", `Protection activated for ${data.user_info.name}`, "success");
            } else if (data.status === "error") {
                clearInterval(pollInterval);
                activeUserCode = null;
                showAuthError(data.message || "MSAL login flow expired or failed.");
            }
        })
        .catch(err => console.warn("MSAL poll warning:", err));
    }, 5000);
}

function completeMsalLogin() {
    if (!activeUserCode) {
        showAuthError("Please generate a code first.");
        return;
    }
    
    fetch(`/api/auth/poll/${activeUserCode}`, { method: "POST" })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            if (pollInterval) clearInterval(pollInterval);
            activeUserCode = null;
            showToast("Microsoft login complete", `Protection activated for ${data.user_info.name}`, "success");
        } else if (data.status === "pending") {
            showAuthError("Authentication is still pending. Approve the request on the Microsoft website.");
        } else {
            showAuthError(data.message || "Login verification failed.");
        }
    })
    .catch(err => showAuthError("Verification error: " + err.message));
}

function logout() {
    if (pollInterval) clearInterval(pollInterval);
    activeUserCode = null;
    
    fetch("/api/auth/logout", { method: "POST" })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            showToast("Signed Out", "Microsoft account protection disabled.", "warning");
        }
    })
    .catch(err => console.error("Logout error:", err));
}

function submitPasswordLogin() {
    const email = document.getElementById("auth-pass-email").value.trim();
    const password = document.getElementById("auth-pass-password").value;
    
    if (!email || !email.includes("@")) {
        showAuthError("Please enter a valid Microsoft account email address.");
        return;
    }
    if (!password) {
        showAuthError("Please enter your password.");
        return;
    }
    
    hideAuthError();
    
    fetch("/api/auth/password-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, password: password })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            showToast("Authenticated successfully", `System protection active for ${data.user_info.name}`, "success");
        } else {
            showAuthError(data.message || "Failed to log in.");
        }
    })
    .catch(err => {
        console.error("Password login error:", err);
        showAuthError("Network error. Make sure backend is running.");
    });
}
