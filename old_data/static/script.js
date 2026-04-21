let currentVulnId = null;

// Загрузка данных при запуске
document.addEventListener('DOMContentLoaded', function() {
    loadSoftware();
    loadVulnerabilities();
    loadStats();
    loadSchedule();

    // Обновление каждые 30 секунд
    setInterval(() => {
        loadVulnerabilities();
        loadStats();
    }, 30000);
});

// Загрузка списка ПО
async function loadSoftware() {
    try {
        const response = await fetch('/api/software');
        const software = await response.json();

        const softwareList = document.getElementById('software-list');
        const softwareSelect = document.getElementById('software-select');

        softwareList.innerHTML = '';
        softwareSelect.innerHTML = '<option value="">Select software to scan</option>';

        software.forEach(name => {
            const item = document.createElement('div');
            item.className = 'software-item';
            item.onclick = () => selectSoftware(name);
            item.innerHTML = `
                <span>${name}</span>
                <span class="delete-software" onclick="event.stopPropagation(); deleteSoftware('${name}')">✕</span>
            `;
            softwareList.appendChild(item);

            const option = document.createElement('option');
            option.value = name;
            option.textContent = name;
            softwareSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading software:', error);
    }
}

// Загрузка настроек расписания
async function loadSchedule() {
    try {
        const response = await fetch('/api/schedule');
        const schedule = await response.json();

        document.getElementById('schedule-enabled').checked = schedule.enabled;
        document.getElementById('schedule-age-limit').value = schedule.vuln_age_days;

        const infoDiv = document.getElementById('schedule-info');
        if (schedule.last_scan) {
            const lastScan = new Date(schedule.last_scan).toLocaleString();
            infoDiv.innerHTML = `Last scan: ${lastScan}<br>Next scan: Daily at 03:00`;
        } else {
            infoDiv.innerHTML = 'No scans performed yet. Next scan: Daily at 03:00';
        }
    } catch (error) {
        console.error('Error loading schedule:', error);
    }
}

// Обновление расписания
async function updateSchedule() {
    const enabled = document.getElementById('schedule-enabled').checked;
    const vulnAgeDays = parseInt(document.getElementById('schedule-age-limit').value);

    try {
        const response = await fetch('/api/schedule', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                enabled: enabled,
                vuln_age_days: vulnAgeDays
            })
        });

        const result = await response.json();
        if (result.success) {
            showNotification('Schedule updated successfully', 'success');
        }
    } catch (error) {
        console.error('Error updating schedule:', error);
        showNotification('Error updating schedule', 'error');
    }
}

// Экспорт отчета
async function exportReport() {
    const status = document.getElementById('status-filter').value;
    const severity = document.getElementById('severity-filter').value;

    let url = '/api/vulnerabilities/export?';
    const params = [];
    if (status) params.push(`status=${status}`);
    if (severity) params.push(`severity=${severity}`);
    url += params.join('&');

    window.location.href = url;
}

// Показать уведомление
function showNotification(message, type) {
    const statusDiv = document.getElementById('scan-status');
    statusDiv.style.display = 'block';
    statusDiv.textContent = message;
    statusDiv.style.color = type === 'error' ? 'var(--critical)' : 'var(--secure)';

    setTimeout(() => {
        statusDiv.style.display = 'none';
    }, 5000);
}

function selectSoftware(name) {
    document.querySelectorAll('.software-item').forEach(item => {
        item.classList.remove('selected');
    });

    event.currentTarget.classList.add('selected');
    document.getElementById('software-select').value = name;
}

function showUploadModal() {
    document.getElementById('upload-modal').style.display = 'block';
}

async function uploadSoftwareFile() {
    const fileInput = document.getElementById('software-file');
    const file = fileInput.files[0];

    if (!file) {
        alert('Please select a file');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/software/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.success) {
            document.getElementById('upload-modal').style.display = 'none';
            loadSoftware();
            showNotification('Software list updated successfully', 'success');
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        console.error('Error uploading file:', error);
        showNotification('Error uploading file', 'error');
    }
}

function showAddSoftware() {
    document.getElementById('software-modal').style.display = 'block';
}

async function addSoftware() {
    const name = document.getElementById('new-software').value.trim();
    if (!name) return;

    try {
        const response = await fetch('/api/software', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name: name})
        });

        const result = await response.json();
        if (result.success) {
            document.getElementById('software-modal').style.display = 'none';
            document.getElementById('new-software').value = '';
            loadSoftware();
            showNotification('Software added successfully', 'success');
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        console.error('Error adding software:', error);
        showNotification('Error adding software', 'error');
    }
}

async function deleteSoftware(name) {
    if (!confirm(`Delete ${name} from database?`)) return;

    try {
        const response = await fetch(`/api/software/${encodeURIComponent(name)}`, {
            method: 'DELETE'
        });

        const result = await response.json();
        if (result.success) {
            loadSoftware();
            loadVulnerabilities();
            showNotification('Software deleted', 'success');
        }
    } catch (error) {
        console.error('Error deleting software:', error);
        showNotification('Error deleting software', 'error');
    }
}

async function scanSoftware() {
    const software = document.getElementById('software-select').value;
    const vulnAgeDays = parseInt(document.getElementById('scan-age-limit').value);

    if (!software) {
        showNotification('Select software to scan', 'error');
        return;
    }

    const statusDiv = document.getElementById('scan-status');
    statusDiv.style.display = 'block';
    statusDiv.textContent = 'SCANNING IN PROGRESS...';
    statusDiv.style.color = 'var(--primary)';

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({software: software, vuln_age_days: vulnAgeDays})
        });

        const result = await response.json();
        if (result.success) {
            statusDiv.textContent = `SCAN COMPLETE: ${result.new_vulnerabilities} NEW VULNERABILITIES FOUND`;
            statusDiv.style.color = 'var(--secure)';
            loadVulnerabilities();
            loadStats();
            loadSchedule();
        } else {
            statusDiv.textContent = `ERROR: ${result.error}`;
            statusDiv.style.color = 'var(--critical)';
        }
    } catch (error) {
        statusDiv.textContent = `ERROR: ${error.message}`;
        statusDiv.style.color = 'var(--critical)';
    }
}

async function scanAllSoftware() {
    const vulnAgeDays = parseInt(document.getElementById('scan-age-limit').value);

    if (!confirm('Start scanning all software? This may take a while.')) return;

    const statusDiv = document.getElementById('scan-status');
    statusDiv.style.display = 'block';
    statusDiv.textContent = 'SCANNING ALL SOFTWARE...';
    statusDiv.style.color = 'var(--primary)';

    try {
        const response = await fetch('/api/scan/all', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({vuln_age_days: vulnAgeDays})
        });

        const result = await response.json();
        if (result.success) {
            statusDiv.textContent = 'SCAN STARTED FOR ALL SOFTWARE';
            statusDiv.style.color = 'var(--secure)';
            setTimeout(() => {
                loadVulnerabilities();
                loadStats();
                loadSchedule();
            }, 5000);
        } else {
            statusDiv.textContent = `ERROR: ${result.error}`;
            statusDiv.style.color = 'var(--critical)';
        }
    } catch (error) {
        statusDiv.textContent = `ERROR: ${error.message}`;
        statusDiv.style.color = 'var(--critical)';
    }
}

async function loadVulnerabilities() {
    const status = document.getElementById('status-filter').value;
    const severity = document.getElementById('severity-filter').value;
    const sortBy = document.getElementById('sort-select').value;

    let url = '/api/vulnerabilities?';
    const params = [];
    if (status) params.push(`status=${status}`);
    if (severity) params.push(`severity=${severity}`);
    if (sortBy) params.push(`sort_by=${sortBy}`);
    params.push('sort_order=desc');

    url += params.join('&');

    try {
        const response = await fetch(url);
        const vulnerabilities = await response.json();

        const vulnList = document.getElementById('vuln-list');
        vulnList.innerHTML = '';

        if (vulnerabilities.length === 0) {
            vulnList.innerHTML = '<div style="text-align: center; padding: 40px;">No vulnerabilities found</div>';
            return;
        }

        vulnerabilities.forEach(vuln => {
            const item = document.createElement('div');
            item.className = `vuln-item ${vuln.status}`;
            item.onclick = () => showVulnDetail(vuln);

            const ageDisplay = vuln.vuln_age_days > 0 ? `${vuln.vuln_age_days}d` : vuln.vuln_age;

            item.innerHTML = `
                <div class="vuln-header">
                    <span class="vuln-id">${vuln.id}</span>
                    <span class="vuln-cvss">CVSS: ${vuln.cvss || 'N/A'}</span>
                </div>
                <div class="vuln-title">${vuln.name}</div>
                <div class="vuln-meta">
                    <span><i>>_</i> ${vuln.software}</span>
                    <span><i>⚡</i> ${vuln.severity || 'MEDIUM'}</span>
                    <span><i>⌛</i> Age: ${ageDisplay}</span>
                    ${vuln.exploits_available ? '<span><i>💀</i> EXPLOITS</span>' : ''}
                    ${vuln.kev ? '<span><i>🔥</i> KEV</span>' : ''}
                </div>
                ${vuln.comment ? `<div class="vuln-comment">// ${vuln.comment}</div>` : ''}
            `;

            vulnList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
    }
}

function showVulnDetail(vuln) {
    currentVulnId = vuln.id;

    const modal = document.getElementById('vuln-detail-modal');
    const content = document.getElementById('vuln-detail-content');
    const statusSelect = document.getElementById('detail-status');
    const commentInput = document.getElementById('detail-comment');

    document.getElementById('detail-cve-id').textContent = vuln.id;

    content.innerHTML = `
        <div style="margin-bottom: 20px;">
            <strong style="color: var(--primary);">${vuln.name}</strong>
        </div>
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px;">
            <div>CVSS: <span style="color: ${vuln.cvss >= 9 ? 'var(--critical)' : 'var(--primary)'}">${vuln.cvss || 'N/A'}</span></div>
            <div>Severity: <span style="color: ${vuln.severity === 'CRITICAL' ? 'var(--critical)' : 'var(--primary)'}">${vuln.severity || 'N/A'}</span></div>
            <div>EPSS: ${vuln.epss || 'N/A'}</div>
            <div>Vuln Age: ${vuln.vuln_age_days ? vuln.vuln_age_days + ' days' : vuln.vuln_age || 'N/A'}</div>
            <div>Exposure: ${vuln.exposure || 'N/A'}</div>
            <div>KEV: ${vuln.kev ? '✔' : '✘'}</div>
        </div>
        <div style="margin-bottom: 20px;">
            <div>Vendors: ${vuln.vendors || 'N/A'}</div>
            <div>Products: ${vuln.products || 'N/A'}</div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 5px; margin-bottom: 20px;">
            <div style="color: ${vuln.exploits_available ? 'var(--critical)' : '#888'}">Exploits: ${vuln.exploits_available ? '✔' : '✘'}</div>
            <div style="color: ${vuln.patch_available ? 'var(--secure)' : '#888'}">Patch: ${vuln.patch_available ? '✔' : '✘'}</div>
            <div style="color: ${vuln.pocs_available ? 'var(--warning)' : '#888'}">POCs: ${vuln.pocs_available ? '✔' : '✘'}</div>
            <div style="color: ${vuln.nuclei_template ? 'var(--primary)' : '#888'}">Nuclei: ${vuln.nuclei_template ? '✔' : '✘'}</div>
        </div>
        <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--primary);">
            <strong>Raw Output:</strong>
            <pre style="margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.5); overflow-x: auto; white-space: pre-wrap; font-size: 0.8rem;">${escapeHtml(vuln.raw_output || 'No raw output available')}</pre>
        </div>
    `;

    statusSelect.value = vuln.status;
    commentInput.value = vuln.comment || '';

    modal.style.display = 'block';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function updateVulnerabilityDetail() {
    if (!currentVulnId) return;

    const status = document.getElementById('detail-status').value;
    const comment = document.getElementById('detail-comment').value;

    try {
        const response = await fetch(`/api/vulnerabilities/${currentVulnId}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({status: status, comment: comment})
        });

        const result = await response.json();
        if (result.success) {
            document.getElementById('vuln-detail-modal').style.display = 'none';
            loadVulnerabilities();
            loadStats();
            showNotification('Vulnerability updated', 'success');
        }
    } catch (error) {
        console.error('Error updating vulnerability:', error);
        showNotification('Error updating vulnerability', 'error');
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();

        document.getElementById('total-vulns').textContent = stats.total;
        document.getElementById('new-vulns').textContent = stats.new;
        document.getElementById('in-progress-vulns').textContent = stats.in_progress;
        document.getElementById('closed-vulns').textContent = stats.closed;

        if (stats.schedule && stats.schedule.last_scan) {
            const lastScan = new Date(stats.schedule.last_scan).toLocaleString();
            document.getElementById('last-scan').textContent = lastScan;
        }

        const threatLevel = document.getElementById('threat-level');
        if (stats.critical > 0) {
            threatLevel.textContent = 'CRITICAL';
            threatLevel.style.color = 'var(--critical)';
        } else if (stats.high > 0) {
            threatLevel.textContent = 'HIGH';
            threatLevel.style.color = 'var(--warning)';
        } else {
            threatLevel.textContent = 'MONITORING';
            threatLevel.style.color = 'var(--secure)';
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

document.querySelectorAll('.close').forEach(close => {
    close.onclick = function() {
        this.closest('.modal').style.display = 'none';
    }
});

window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
    }
}

document.getElementById('status-filter').addEventListener('change', loadVulnerabilities);
document.getElementById('severity-filter').addEventListener('change', loadVulnerabilities);
document.getElementById('sort-select').addEventListener('change', loadVulnerabilities);