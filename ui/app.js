/**
 * ARNIE AI — Chat Interface & Automation Platform
 * Ansible Remediation & Navigation Intelligence Engine
 * Built on RMCP by BLCKBX
 */

const API_BASE = 'http://localhost:8085';
let conversationId = null;
let isGenerating = false;
let activeFilter = 'all';

// ── DOM refs ──
const chatInput = document.getElementById('chatInput');
const sendBtn = document.getElementById('sendBtn');
const messagesEl = document.getElementById('messages');
const welcomeScreen = document.getElementById('welcomeScreen');
const approvalsList = document.getElementById('approvalsList');
const jobsList = document.getElementById('jobsList');

// ══════════════════════════════════════════
// Library Data — 50 Playbook Templates
// ══════════════════════════════════════════

const LIBRARY_CATEGORIES = [
  'All', 'Namespace', 'Deployment', 'RBAC', 'Networking', 'Storage',
  'Operators', 'Secrets', 'Monitoring', 'Backup', 'Cluster Ops'
];

const LIBRARY_TEMPLATES = [
  // ── Namespace Management ──
  { id: 1, title: 'Create Namespace', desc: 'Create a new namespace with labels and annotations', category: 'Namespace', risk: 'low', prompt: 'Create a namespace called {name} with standard labels' },
  { id: 2, title: 'Namespace with Resource Quotas', desc: 'Namespace with CPU, memory, and pod count quotas', category: 'Namespace', risk: 'low', prompt: 'Create a namespace with resource quotas: 4 CPU, 8Gi memory, 20 pods max' },
  { id: 3, title: 'Namespace with Network Isolation', desc: 'Namespace with deny-all default network policy', category: 'Namespace', risk: 'medium', prompt: 'Create a namespace with default deny-all network policy and only allow DNS egress' },
  { id: 4, title: 'Namespace with LimitRange', desc: 'Namespace with default container resource limits', category: 'Namespace', risk: 'low', prompt: 'Create a namespace with LimitRange: default 256Mi memory, 250m CPU per container' },
  { id: 5, title: 'Delete Namespace', desc: 'Safely delete a namespace and all resources within it', category: 'Namespace', risk: 'critical', prompt: 'Delete namespace {name} after confirming no running workloads' },

  // ── Deployments & Scaling ──
  { id: 6, title: 'Deploy Application', desc: 'Create Deployment, Service, and Route', category: 'Deployment', risk: 'medium', prompt: 'Deploy {app} with 3 replicas, a ClusterIP service on port 8080, and an OpenShift route' },
  { id: 7, title: 'Scale Deployment', desc: 'Scale a deployment to a specified replica count', category: 'Deployment', risk: 'low', prompt: 'Scale deployment {name} in {namespace} to {count} replicas' },
  { id: 8, title: 'Rolling Update', desc: 'Update container image with zero-downtime rolling strategy', category: 'Deployment', risk: 'medium', prompt: 'Update deployment {name} to image {image}:{tag} with rolling update strategy' },
  { id: 9, title: 'Canary Deployment', desc: 'Deploy canary version alongside stable', category: 'Deployment', risk: 'medium', prompt: 'Create a canary deployment of {app} with 1 replica alongside the stable version' },
  { id: 10, title: 'HPA Configuration', desc: 'Set up Horizontal Pod Autoscaler', category: 'Deployment', risk: 'low', prompt: 'Create HPA for deployment {name} with min 2, max 10 replicas, target 70% CPU' },
  { id: 11, title: 'StatefulSet Deploy', desc: 'Deploy a StatefulSet with persistent storage', category: 'Deployment', risk: 'medium', prompt: 'Deploy a StatefulSet for {app} with 3 replicas and 50Gi PVC per pod' },
  { id: 12, title: 'DaemonSet Deploy', desc: 'Deploy a DaemonSet across all worker nodes', category: 'Deployment', risk: 'medium', prompt: 'Deploy a DaemonSet running {image} on all worker nodes' },

  // ── RBAC & Security ──
  { id: 13, title: 'Read-Only ClusterRole', desc: 'Cluster-wide read-only access role', category: 'RBAC', risk: 'low', prompt: 'Create a ClusterRole with read-only access to all resources and bind it to group {group}' },
  { id: 14, title: 'Namespace Admin Role', desc: 'Full admin access within a single namespace', category: 'RBAC', risk: 'medium', prompt: 'Create a Role with full access in namespace {namespace} and bind to user {user}' },
  { id: 15, title: 'Service Account with RBAC', desc: 'Create SA with specific permissions', category: 'RBAC', risk: 'medium', prompt: 'Create a service account {name} with read access to secrets and configmaps in {namespace}' },
  { id: 16, title: 'Remove User Access', desc: 'Revoke a user\'s role bindings', category: 'RBAC', risk: 'high', prompt: 'Remove all RoleBindings and ClusterRoleBindings for user {user}' },
  { id: 17, title: 'SCC Configuration', desc: 'Create or assign SecurityContextConstraints', category: 'RBAC', risk: 'high', prompt: 'Grant anyuid SCC to service account {sa} in namespace {namespace}' },
  { id: 18, title: 'Audit RBAC Permissions', desc: 'List all roles and bindings for a namespace', category: 'RBAC', risk: 'low', prompt: 'List all Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings in namespace {namespace}' },

  // ── Networking ──
  { id: 19, title: 'Allow Ingress from Namespace', desc: 'Network policy allowing traffic from specific namespace', category: 'Networking', risk: 'medium', prompt: 'Create a NetworkPolicy allowing ingress from namespace {source} to pods with label app={app} on port {port}' },
  { id: 20, title: 'Deny All Ingress', desc: 'Default deny-all ingress policy', category: 'Networking', risk: 'high', prompt: 'Create a deny-all ingress NetworkPolicy in namespace {namespace}' },
  { id: 21, title: 'Allow Egress to DNS Only', desc: 'Restrict egress to DNS resolution only', category: 'Networking', risk: 'high', prompt: 'Create a NetworkPolicy allowing only DNS egress (port 53) in namespace {namespace}' },
  { id: 22, title: 'Create OpenShift Route', desc: 'Expose a service via OpenShift route with TLS', category: 'Networking', risk: 'low', prompt: 'Create an edge-terminated TLS route for service {service} in namespace {namespace}' },
  { id: 23, title: 'Create Ingress', desc: 'Create an Ingress resource with host routing', category: 'Networking', risk: 'low', prompt: 'Create an Ingress for host {host} routing to service {service} on port 80' },
  { id: 24, title: 'Service Mesh Policy', desc: 'Create Istio AuthorizationPolicy', category: 'Networking', risk: 'medium', prompt: 'Create an Istio AuthorizationPolicy allowing only {source} to access {destination}' },

  // ── Storage ──
  { id: 25, title: 'Create PVC', desc: 'Provision a PersistentVolumeClaim', category: 'Storage', risk: 'low', prompt: 'Create a {size} PVC with storage class {sc} in namespace {namespace}' },
  { id: 26, title: 'Expand PVC', desc: 'Resize an existing PersistentVolumeClaim', category: 'Storage', risk: 'medium', prompt: 'Expand PVC {name} in {namespace} to {newSize}' },
  { id: 27, title: 'Create StorageClass', desc: 'Define a new StorageClass', category: 'Storage', risk: 'medium', prompt: 'Create a StorageClass using provisioner {provisioner} with reclaimPolicy Retain' },
  { id: 28, title: 'Migrate PV Data', desc: 'Copy data between PersistentVolumes', category: 'Storage', risk: 'high', prompt: 'Create a job to copy data from PVC {source} to PVC {destination} in namespace {namespace}' },
  { id: 29, title: 'Snapshot PVC', desc: 'Create a VolumeSnapshot of a PVC', category: 'Storage', risk: 'low', prompt: 'Create a VolumeSnapshot of PVC {name} in namespace {namespace}' },

  // ── Operators ──
  { id: 30, title: 'Install Operator', desc: 'Install an operator via OLM Subscription', category: 'Operators', risk: 'medium', prompt: 'Install the {operator} operator from OperatorHub in namespace {namespace}' },
  { id: 31, title: 'Upgrade Operator', desc: 'Update an operator to a new channel/version', category: 'Operators', risk: 'medium', prompt: 'Update the {operator} operator subscription to channel {channel}' },
  { id: 32, title: 'Remove Operator', desc: 'Uninstall an operator and its resources', category: 'Operators', risk: 'high', prompt: 'Remove the {operator} operator, its CSV, subscription, and CRDs' },
  { id: 33, title: 'Create Operator CR', desc: 'Create a Custom Resource for an installed operator', category: 'Operators', risk: 'medium', prompt: 'Create a {kind} custom resource for the {operator} operator with default settings' },

  // ── Secrets & Config ──
  { id: 34, title: 'Create Secret', desc: 'Create an opaque secret with key-value pairs', category: 'Secrets', risk: 'medium', prompt: 'Create a secret {name} in {namespace} with keys username and password' },
  { id: 35, title: 'Create TLS Secret', desc: 'Create a TLS secret from cert and key', category: 'Secrets', risk: 'medium', prompt: 'Create a TLS secret {name} from certificate and key files' },
  { id: 36, title: 'Rotate Secret', desc: 'Update a secret with new values', category: 'Secrets', risk: 'high', prompt: 'Rotate secret {name} in {namespace} with new generated password' },
  { id: 37, title: 'Create ConfigMap', desc: 'Create a ConfigMap from literal values or file', category: 'Secrets', risk: 'low', prompt: 'Create a ConfigMap {name} in {namespace} with configuration data' },
  { id: 38, title: 'Copy Secret Cross-Namespace', desc: 'Copy a secret from one namespace to another', category: 'Secrets', risk: 'medium', prompt: 'Copy secret {name} from namespace {source} to namespace {destination}' },

  // ── Monitoring ──
  { id: 39, title: 'Create PrometheusRule', desc: 'Define alerting rules for Prometheus', category: 'Monitoring', risk: 'low', prompt: 'Create a PrometheusRule with alerts for high CPU, memory, and pod restarts' },
  { id: 40, title: 'Deploy ServiceMonitor', desc: 'Configure Prometheus to scrape a service', category: 'Monitoring', risk: 'low', prompt: 'Create a ServiceMonitor for service {service} scraping /metrics on port {port}' },
  { id: 41, title: 'Create Grafana Dashboard', desc: 'Deploy a Grafana dashboard ConfigMap', category: 'Monitoring', risk: 'low', prompt: 'Create a Grafana dashboard ConfigMap for monitoring namespace {namespace}' },
  { id: 42, title: 'Configure AlertManager', desc: 'Set up alert routing and receivers', category: 'Monitoring', risk: 'medium', prompt: 'Configure AlertManager to send critical alerts to Slack channel {channel}' },

  // ── Backup & Recovery ──
  { id: 43, title: 'Backup Namespace', desc: 'Export all resources from a namespace', category: 'Backup', risk: 'low', prompt: 'Export all resources from namespace {namespace} to YAML files' },
  { id: 44, title: 'Restore from Backup', desc: 'Apply backed-up resources to a namespace', category: 'Backup', risk: 'high', prompt: 'Restore namespace {namespace} from backup files' },
  { id: 45, title: 'Database Backup Job', desc: 'Create a CronJob for database backups', category: 'Backup', risk: 'low', prompt: 'Create a CronJob that backs up PostgreSQL database daily to PVC {pvc}' },

  // ── Cluster Operations ──
  { id: 46, title: 'Drain Node', desc: 'Cordon and drain a node for maintenance', category: 'Cluster Ops', risk: 'high', prompt: 'Cordon and drain node {node} with grace period 300 seconds' },
  { id: 47, title: 'Label Nodes', desc: 'Add or update labels on cluster nodes', category: 'Cluster Ops', risk: 'medium', prompt: 'Add label {key}={value} to nodes matching selector {selector}' },
  { id: 48, title: 'Taint Node', desc: 'Add taints to a node for workload scheduling', category: 'Cluster Ops', risk: 'medium', prompt: 'Add taint {key}={value}:NoSchedule to node {node}' },
  { id: 49, title: 'Cluster Health Check', desc: 'Verify cluster health across all components', category: 'Cluster Ops', risk: 'low', prompt: 'Check cluster health: node status, etcd health, API server, pending pods' },
  { id: 50, title: 'Certificate Rotation', desc: 'Rotate cluster certificates before expiry', category: 'Cluster Ops', risk: 'critical', prompt: 'Check certificate expiry dates and rotate any expiring within 30 days' },
];

// ══════════════════════════════════════════
// Init
// ══════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    chatInput.addEventListener('keydown', handleKeyDown);
    chatInput.addEventListener('input', autoResize);
    checkConnections();
    loadApprovals();
    loadAudit();
    renderLibrary();
    setInterval(checkConnections, 30000);
    setInterval(loadApprovals, 15000);
});

// ══════════════════════════════════════════
// Tab Switching
// ══════════════════════════════════════════

function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

    document.querySelector(`.tab[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`tab-${tabName}`).classList.add('active');

    // Show/hide sidebar (only for chat)
    const sidebar = document.getElementById('sidebar');
    sidebar.style.display = tabName === 'chat' ? 'flex' : 'none';

    // Load data for specific tabs
    if (tabName === 'audit') loadAudit();
    if (tabName === 'playbooks') loadPlaybooks();
    if (tabName === 'integrations') checkConnections();
}

// ══════════════════════════════════════════
// Chat
// ══════════════════════════════════════════

function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize() {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 150) + 'px';
}

async function sendMessage() {
    const message = chatInput.value.trim();
    if (!message || isGenerating) return;

    isGenerating = true;
    sendBtn.disabled = true;
    welcomeScreen.style.display = 'none';
    messagesEl.classList.add('active');
    appendMessage('user', message);
    chatInput.value = '';
    chatInput.style.height = 'auto';
    showTyping();

    try {
        const resp = await fetch(`${API_BASE}/ai/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, conversation_id: conversationId, context: {} }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        conversationId = data.conversation_id;
        hideTyping();
        if (data.playbook) { appendPlaybookMessage(data); }
        else { appendMessage('agent', data.response); }
        loadApprovals();
    } catch (err) {
        hideTyping();
        appendMessage('agent', `Connection error: ${err.message}. Make sure the ARNIE backend is running.`);
    }

    isGenerating = false;
    sendBtn.disabled = false;
    chatInput.focus();
}

function usePrompt(text) {
    switchTab('chat');
    chatInput.value = text;
    chatInput.focus();
    autoResize();
}

function appendMessage(role, content) {
    const el = document.createElement('div');
    el.className = `message ${role}`;
    const avatar = role === 'user' ? 'U' : '🤖';
    const avatarClass = role === 'user' ? 'user-avatar' : 'agent-avatar';
    const sender = role === 'user' ? 'You' : 'ARNIE';
    el.innerHTML = `
        <div class="message-header">
            <div class="message-avatar ${avatarClass}">${avatar}</div>
            <div class="message-sender">${sender}</div>
        </div>
        <div class="message-body">${formatContent(content)}</div>`;
    messagesEl.appendChild(el);
    scrollToBottom();
}

function appendPlaybookMessage(data) {
    const el = document.createElement('div');
    el.className = 'message agent';
    const pb = data.playbook;
    const riskClass = pb.risk_level || 'medium';
    const validation = pb.validation?.valid ? '✅ Passed' : '❌ Issues found';
    const blastSummary = pb.blast_radius?.summary || 'N/A';
    el.innerHTML = `
        <div class="message-header">
            <div class="message-avatar agent-avatar">🤖</div>
            <div class="message-sender">ARNIE</div>
        </div>
        <div class="message-body">
            <p>${formatContent(data.response.split('```')[0])}</p>
            <div class="playbook-block">
                <div class="playbook-block-header">
                    <span class="playbook-block-title">${pb.file_name || 'playbook.yml'}</span>
                    <span class="risk-badge ${riskClass}">${riskClass.toUpperCase()}</span>
                </div>
                <div class="playbook-block-body"><pre><code>${escapeHtml(pb.yaml_content)}</code></pre></div>
            </div>
            <div style="font-size:13px;color:var(--text-secondary);margin:8px 0;">
                <strong>Blast Radius:</strong> ${blastSummary} &nbsp;|&nbsp; <strong>Validation:</strong> ${validation}
            </div>
       <div class="approval-bar">
                <button class="${!pb.validation?.valid ? 'btn btn-approve has-issues' : 'btn btn-approve'}" onclick="approvePlaybook('${pb.approval_id}')">${!pb.validation?.valid ? '⚠ Approve Anyway' : '✓ Approve & Deploy'}</button>
                <button class="${!pb.validation?.valid ? 'btn btn-edit suggested' : 'btn btn-edit'}" onclick="viewApprovalEdit('${pb.approval_id}')">Edit</button>
                <button class="btn btn-reject" onclick="rejectPlaybook('${pb.approval_id}')">Reject</button>
            </div>
        </div>`;
    messagesEl.appendChild(el);
    scrollToBottom();
}

// ══════════════════════════════════════════
// Approval Actions
// ══════════════════════════════════════════

async function approvePlaybook(approvalId) {
    appendMessage('agent', '⏳ Approving playbook, pushing to GitHub, and launching AAP job...');
    showTyping();
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ actor: 'operator', reason: 'Approved via ARNIE UI' }),
        });
        hideTyping();
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        let msg = '✅ **Playbook approved!**\n\n';
        if (data.github) msg += `📦 **GitHub:** Committed \`${data.github.commit_sha?.slice(0,8)}\` to \`${data.github.repo}\`\n`;
        if (data.aap) msg += `🚀 **AAP:** Job \`${data.aap.job_id}\` launched — status: ${data.aap.status}\n`;
        appendMessage('agent', msg);
        loadApprovals();
    } catch (err) {
        hideTyping();
        appendMessage('agent', `❌ Approval failed: ${err.message}`);
    }
}

async function rejectPlaybook(approvalId) {
    try {
        await fetch(`${API_BASE}/ai/approvals/${approvalId}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ actor: 'operator', reason: 'Rejected via ARNIE UI' }),
        });
        appendMessage('agent', '🚫 Playbook rejected. No changes were made.');
        loadApprovals();
    } catch (err) { appendMessage('agent', `❌ Rejection failed: ${err.message}`); }
}

function openEditModal(approvalId, yamlContent) {
    const modal = document.getElementById('playbookModal');
    document.getElementById('modalTitle').textContent = 'Edit Playbook';
    const pb = document.getElementById('modalPlaybook');
    pb.contentEditable = true;
    pb.textContent = yamlContent;
    pb.style.outline = 'none';
    pb.style.minHeight = '300px';
    document.getElementById('modalActions').innerHTML = `
        <button class="btn btn-reject" onclick="closeModal()">Cancel</button>
        <button class="btn btn-approve" onclick="saveEdit('${approvalId}')">Save & Re-validate</button>`;
    modal.classList.add('active');
}

async function saveEdit(approvalId) {
    const newYaml = document.getElementById('modalPlaybook').textContent;
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}/edit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ yaml_content: newYaml }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        closeModal();
        appendMessage('agent', `✏️ Playbook updated. Validation: ${data.validation?.valid ? '✅ Passed' : '❌ Issues found'}`);
    } catch (err) { appendMessage('agent', `❌ Edit failed: ${err.message}`); }
}

function closeModal() { document.getElementById('playbookModal').classList.remove('active'); }

// ══════════════════════════════════════════
// Library
// ══════════════════════════════════════════

function renderLibrary() {
    const filtersEl = document.getElementById('libraryFilters');
    filtersEl.innerHTML = LIBRARY_CATEGORIES.map(cat => {
        const cls = (cat === 'All' && activeFilter === 'all') || cat === activeFilter ? 'active' : '';
        return `<button class="filter-pill ${cls}" onclick="setFilter('${cat}')">${cat}</button>`;
    }).join('');

    const gridEl = document.getElementById('libraryGrid');
    const searchVal = (document.getElementById('librarySearch')?.value || '').toLowerCase();

    const filtered = LIBRARY_TEMPLATES.filter(t => {
        const matchCategory = activeFilter === 'all' || activeFilter === 'All' || t.category === activeFilter;
        const matchSearch = !searchVal || t.title.toLowerCase().includes(searchVal) || t.desc.toLowerCase().includes(searchVal) || t.category.toLowerCase().includes(searchVal);
        return matchCategory && matchSearch;
    });

    gridEl.innerHTML = filtered.map(t => {
        const riskColor = { low: 'var(--success)', medium: 'var(--warning)', high: 'var(--error)', critical: '#ff6b6b' }[t.risk] || 'var(--text-muted)';
        return `
        <div class="library-card" onclick="usePrompt('${t.prompt.replace(/'/g, "\\'")}')">
            <div class="library-card-title">${t.title}</div>
            <div class="library-card-desc">${t.desc}</div>
            <div class="library-card-meta">
                <span class="library-card-cat">${t.category}</span>
                <span class="library-card-risk" style="color:${riskColor}">${t.risk.toUpperCase()}</span>
            </div>
        </div>`;
    }).join('');
}

function setFilter(cat) {
    activeFilter = cat === 'All' ? 'all' : cat;
    renderLibrary();
}

function filterLibrary() { renderLibrary(); }

// ══════════════════════════════════════════
// Sidebar
// ══════════════════════════════════════════

async function loadApprovals() {
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals`);
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data.approvals?.length) {
            approvalsList.innerHTML = '<div class="sidebar-empty">No pending approvals</div>';
            return;
        }
        approvalsList.innerHTML = data.approvals.slice(0, 10).map(a => {
            const cls = a.status === 'pending_approval' ? 'pending' : a.status === 'approved' || a.status === 'executed' ? 'approved' : 'failed';
            return `<div class="sidebar-item ${cls}">
                <div class="sidebar-item-title">${a.intent?.slice(0, 40) || a.playbook_id}</div>
                <div class="sidebar-item-meta">${a.status.replace('_', ' ')} • ${a.risk_level || 'medium'}</div>
            </div>`;
        }).join('');
    } catch (e) {}
}

// ══════════════════════════════════════════
// Playbooks History
// ══════════════════════════════════════════

async function loadPlaybooks() {
    const table = document.getElementById('playbooksTable');
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals`);
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data.approvals?.length) {
            table.innerHTML = '<div class="table-empty">No playbooks generated yet. Start a conversation to create one.</div>';
            return;
        }
        table.innerHTML = data.approvals.map(a => `
            <div class="playbook-row" onclick="openEditModal('${a.id}', ${JSON.stringify(JSON.stringify(a.yaml_content || ''))})">
                <div class="playbook-row-name">${a.intent?.slice(0, 60) || a.file_name || 'Untitled'}</div>
                <span class="playbook-row-status ${a.status === 'pending_approval' ? 'pending' : a.status}">${a.status.replace('_', ' ')}</span>
                <span class="risk-badge ${a.risk_level || 'medium'}">${(a.risk_level || 'medium').toUpperCase()}</span>
                <span class="playbook-row-time">${a.created_at?.slice(11, 16) || ''}</span>
            </div>`).join('');
    } catch (e) {
        table.innerHTML = '<div class="table-empty">Unable to load playbooks.</div>';
    }
}

// ══════════════════════════════════════════
// Audit Trail
// ══════════════════════════════════════════

async function loadAudit() {
    const list = document.getElementById('auditList');
    try {
        const resp = await fetch(`${API_BASE}/ai/audit`);
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data.audit?.length) {
            list.innerHTML = '<div class="table-empty">No audit events yet.</div>';
            return;
        }
        list.innerHTML = data.audit.slice(0, 50).map(a => `
            <div class="audit-item">
                <span class="audit-event">${a.event || 'event'}</span>
                <span class="audit-detail">${a.reason || a.approval_id || ''}</span>
                <span class="audit-actor">${a.actor || 'system'}</span>
                <span class="audit-time">${a.created_at?.slice(11, 19) || ''}</span>
            </div>`).join('');
    } catch (e) {}
}

// ══════════════════════════════════════════
// Connection Status
// ══════════════════════════════════════════

async function checkConnections() {
    try {
        const resp = await fetch(`${API_BASE}/git/status`);
        if (resp.ok) {
            const data = await resp.json();
            document.querySelector('#githubStatus .status-dot').className = `status-dot ${data.connected ? 'online' : 'offline'}`;
            const el = document.getElementById('intGithubStatus');
            const dot = document.getElementById('intGithubDot');
            if (el) el.textContent = data.connected ? `Connected — ${data.repo}` : 'Not configured';
            if (dot) dot.className = `integration-dot ${data.connected ? 'online' : 'offline'}`;
        }
    } catch (e) {}
    try {
        const resp = await fetch(`${API_BASE}/aap/status`);
        if (resp.ok) {
            const data = await resp.json();
            document.querySelector('#aapStatus .status-dot').className = `status-dot ${data.connected ? 'online' : 'offline'}`;
            const el = document.getElementById('intAapStatus');
            const dot = document.getElementById('intAapDot');
            if (el) el.textContent = data.connected ? `Connected — ${data.version || 'AAP'}` : 'Not configured';
            if (dot) dot.className = `integration-dot ${data.connected ? 'online' : 'offline'}`;
        }
    } catch (e) {}
}

// ══════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════

function showTyping() {
    let t = document.querySelector('.typing');
    if (!t) {
        t = document.createElement('div');
        t.className = 'typing';
        t.innerHTML = `<div class="message-header"><div class="message-avatar agent-avatar">🤖</div><div class="message-sender">ARNIE</div></div><div class="typing-dots"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div>`;
        messagesEl.appendChild(t);
    }
    t.classList.add('active');
    scrollToBottom();
}

function hideTyping() { const t = document.querySelector('.typing'); if (t) t.remove(); }
function scrollToBottom() { messagesEl.scrollTop = messagesEl.scrollHeight; }
function escapeHtml(t) { const e = document.createElement('div'); e.textContent = t; return e.innerHTML; }

function formatContent(text) {
    if (!text) return '';
    text = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_, l, c) => `<pre><code>${escapeHtml(c.trim())}</code></pre>`);
    text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/\n/g, '<br>');
    return text;
}

// ══════════════════════════════════════════
// Auth & Login
// ══════════════════════════════════════════

let authToken = localStorage.getItem('arnie_token') || null;
let currentUser = null;

function checkAuth() {
    if (authToken) {
        document.getElementById('loginOverlay').classList.add('hidden');
        loadUserProfile();
    } else {
        document.getElementById('loginOverlay').classList.remove('hidden');
    }
}

async function doLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');
    errorEl.textContent = '';

    if (!email || !password) {
        errorEl.textContent = 'Email and password required';
        return;
    }

    try {
        const resp = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        if (resp.status === 401) {
            errorEl.textContent = 'Invalid email or password';
            return;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const data = await resp.json();
        authToken = data.token;
        currentUser = data.account;
        localStorage.setItem('arnie_token', authToken);
        document.getElementById('loginOverlay').classList.add('hidden');

    } catch (err) {
        // If backend doesn't have auth, skip login for dev mode
        console.warn('Auth endpoint not available, running in dev mode');
        authToken = 'dev-mode';
        localStorage.setItem('arnie_token', authToken);
        document.getElementById('loginOverlay').classList.add('hidden');
    }
}

function showSignup() {
    const card = document.querySelector('.login-card');
    const loginSub = document.querySelector('.login-sub');
    const loginBtn = document.querySelector('.login-btn');
    const footer = document.querySelector('.login-footer');

    loginSub.textContent = 'Create your BLCKBX account';
    loginBtn.textContent = 'Create Account';
    loginBtn.onclick = doSignup;
    footer.innerHTML = 'Already have an account? <a href="#" onclick="showLogin()">Sign in</a>';

    // Add name field if not already there
    if (!document.getElementById('signupName')) {
        const nameField = document.createElement('div');
        nameField.className = 'login-field';
        nameField.id = 'signupNameField';
        nameField.innerHTML = '<label>Name</label><input type="text" id="signupName" placeholder="Your name">';
        document.querySelector('.login-field').before(nameField);
    }
}

function showLogin() {
    const loginSub = document.querySelector('.login-sub');
    const loginBtn = document.querySelector('.login-btn');
    const footer = document.querySelector('.login-footer');

    loginSub.textContent = 'Sign in to your BLCKBX account';
    loginBtn.textContent = 'Sign In';
    loginBtn.onclick = doLogin;
    footer.innerHTML = 'Don\'t have an account? <a href="#" onclick="showSignup()">Create one</a>';

    const nameField = document.getElementById('signupNameField');
    if (nameField) nameField.remove();
}

async function doSignup() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const name = document.getElementById('signupName')?.value.trim() || '';
    const errorEl = document.getElementById('loginError');
    errorEl.textContent = '';

    if (!email || !password) {
        errorEl.textContent = 'Email and password required';
        return;
    }
    if (password.length < 8) {
        errorEl.textContent = 'Password must be at least 8 characters';
        return;
    }

    try {
        const resp = await fetch(`${API_BASE}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, name }),
        });
        if (resp.status === 409) {
            errorEl.textContent = 'Account already exists';
            return;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const data = await resp.json();
        authToken = data.token;
        currentUser = data.account;
        localStorage.setItem('arnie_token', authToken);
        document.getElementById('loginOverlay').classList.add('hidden');
    } catch (err) {
        errorEl.textContent = `Signup failed: ${err.message}`;
    }
}

function doLogout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('arnie_token');
    closeSettings();
    document.getElementById('loginOverlay').classList.remove('hidden');
}

async function loadUserProfile() {
    if (!authToken || authToken === 'dev-mode') return;
    try {
        const resp = await fetch(`${API_BASE}/auth/me`, {
            headers: { 'Authorization': `Bearer ${authToken}` },
        });
        if (resp.ok) {
            const data = await resp.json();
            currentUser = data.account;
            if (currentUser) {
                document.getElementById('settingsEmail').value = currentUser.email || '';
                document.getElementById('settingsName').value = currentUser.name || '';
                document.getElementById('settingsOrg').value = currentUser.organization || '';
            }
        }
    } catch (e) {}
}

// ══════════════════════════════════════════
// Settings Modal
// ══════════════════════════════════════════

function openSettings() {
    document.getElementById('settingsModal').classList.add('active');
}

function closeSettings() {
    document.getElementById('settingsModal').classList.remove('active');
}

function switchSettingsTab(section) {
    document.querySelectorAll('.settings-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.settings-section').forEach(s => s.classList.remove('active'));

    document.querySelector(`.settings-nav-btn[data-section="${section}"]`).classList.add('active');
    document.getElementById(`settings-${section}`).classList.add('active');
}

async function saveSettings(section) {
    const statusEl = document.getElementById(`${section}TestStatus`);

    if (section === 'account') {
        const name = document.getElementById('settingsName').value;
        const organization = document.getElementById('settingsOrg').value;
        try {
            if (authToken && authToken !== 'dev-mode') {
                await fetch(`${API_BASE}/auth/me`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`,
                    },
                    body: JSON.stringify({ name, organization }),
                });
            }
            alert('Account saved');
        } catch (e) { alert(`Save failed: ${e.message}`); }
    }

    if (section === 'github') {
        const repo = document.getElementById('settingsGithubRepo').value;
        const token = document.getElementById('settingsGithubToken').value;
        const branch = document.getElementById('settingsGithubBranch').value;
        const dir = document.getElementById('settingsGithubDir').value;
        if (statusEl) { statusEl.textContent = 'Testing...'; statusEl.className = 'form-status'; }
        try {
            const resp = await fetch(`${API_BASE}/settings/github`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repo, token, branch, playbook_dir: dir }),
            });
            if (resp.ok) {
                const data = await resp.json();
                if (statusEl) {
                    statusEl.textContent = data.connected ? '✓ Connected' : '✗ Connection failed';
                    statusEl.className = `form-status ${data.connected ? 'success' : 'error'}`;
                }
            }
        } catch (e) {
            if (statusEl) { statusEl.textContent = `✗ ${e.message}`; statusEl.className = 'form-status error'; }
        }
    }

    if (section === 'aap') {
        const url = document.getElementById('settingsAapUrl').value;
        const token = document.getElementById('settingsAapToken').value;
        const projectId = document.getElementById('settingsAapProject').value;
        const templateId = document.getElementById('settingsAapTemplate').value;
        const verifySsl = document.getElementById('settingsAapVerifySsl').checked;
        if (statusEl) { statusEl.textContent = 'Testing...'; statusEl.className = 'form-status'; }
        try {
            const resp = await fetch(`${API_BASE}/settings/aap`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, token, project_id: projectId, job_template_id: templateId, verify_ssl: verifySsl }),
            });
            if (resp.ok) {
                const data = await resp.json();
                if (statusEl) {
                    statusEl.textContent = data.connected ? '✓ Connected' : '✗ Connection failed';
                    statusEl.className = `form-status ${data.connected ? 'success' : 'error'}`;
                }
            }
        } catch (e) {
            if (statusEl) { statusEl.textContent = `✗ ${e.message}`; statusEl.className = 'form-status error'; }
        }
    }

    if (section === 'ai') {
        const provider = document.getElementById('settingsAiProvider').value;
        const model = document.getElementById('settingsAiModel').value;
        try {
            await fetch(`${API_BASE}/ai/models/provider`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, model }),
            });
            document.getElementById('modelSelect').value = provider === 'claude' ? 'claude' : model;
            alert('AI engine updated');
        } catch (e) { alert(`Save failed: ${e.message}`); }
    }

    if (section === 'cluster') {
        alert('Cluster settings saved');
    }
}


// ── Init auth check ──
document.addEventListener('DOMContentLoaded', () => {
    // Dev mode: skip login if backend doesn't support auth
    checkAuth();
});

// ══════════════════════════════════════════
// Conversation History
// ══════════════════════════════════════════

let conversations = JSON.parse(localStorage.getItem('arnie_conversations') || '[]');
let activeConversationId = null;

function newChat() {
    // Save current conversation if it has messages
    if (conversationId && messagesEl.children.length > 0) {
        saveConversation();
    }

    // Reset state
    conversationId = null;
    activeConversationId = null;
    messagesEl.innerHTML = '';
    messagesEl.classList.remove('active');
    welcomeScreen.style.display = 'flex';
    chatInput.value = '';
    chatInput.focus();
    renderConversations();
}

function saveConversation() {
    if (!conversationId) return;

    // Get first user message as title
    const firstUserMsg = messagesEl.querySelector('.message.user .message-body');
    const title = firstUserMsg ? firstUserMsg.textContent.trim().slice(0, 50) : 'New conversation';

    // Count playbooks in this conversation
    const playbookCount = messagesEl.querySelectorAll('.playbook-block').length;

    const existing = conversations.findIndex(c => c.id === conversationId);
    const conv = {
        id: conversationId,
        title: title,
        playbooks: playbookCount,
        updated: new Date().toISOString(),
        messageCount: messagesEl.querySelectorAll('.message').length,
    };

    if (existing >= 0) {
        conversations[existing] = conv;
    } else {
        conversations.unshift(conv);
    }

    // Keep last 20 conversations
    conversations = conversations.slice(0, 20);
    localStorage.setItem('arnie_conversations', JSON.stringify(conversations));
    renderConversations();
}

function renderConversations() {
    const list = document.getElementById('conversationsList');
    if (!list) return;

    if (!conversations.length) {
        list.innerHTML = '<div class="sidebar-empty">Start a conversation</div>';
        return;
    }

    list.innerHTML = conversations.map(c => {
        const isActive = c.id === conversationId;
        const time = formatTimeAgo(c.updated);
        const iconClass = isActive ? 'conv-icon active-conv' : 'conv-icon';

        return `
            <div class="sidebar-item ${isActive ? 'active' : ''}" onclick="loadConversation('${c.id}')">
                <div class="conv-item">
                    <div class="${iconClass}">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>
                    </div>
                    <div class="conv-details">
                        <div class="conv-title">${escapeHtml(c.title)}</div>
                        <div class="conv-meta">
                            <span>${time}</span>
                            ${c.playbooks ? `<span class="conv-playbook-count"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>${c.playbooks}</span>` : ''}
                        </div>
                    </div>
                </div>
            </div>`;
    }).join('');
}

function loadConversation(convId) {
    // Save current conversation first
    if (conversationId && messagesEl.children.length > 0) {
        saveConversation();
    }

    conversationId = convId;
    activeConversationId = convId;
    welcomeScreen.style.display = 'none';
    messagesEl.classList.add('active');

    // Load from backend if available
    fetch(`${API_BASE}/ai/conversations/${convId}`)
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (data && data.recent_turns) {
                messagesEl.innerHTML = '';
                data.recent_turns.forEach(turn => {
                    appendMessage(turn.role === 'user' ? 'user' : 'agent', turn.content);
                });
            }
            renderConversations();
        })
        .catch(() => {
            renderConversations();
        });
}

function formatTimeAgo(dateStr) {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString();
}

// ── Update sendMessage to save conversations ──
const originalSendMessage = sendMessage;
sendMessage = async function() {
    await originalSendMessage();
    saveConversation();
};

// ── Update loadApprovals to show count badge ──
const originalLoadApprovals = loadApprovals;
loadApprovals = async function() {
    await originalLoadApprovals();
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals`);
        if (resp.ok) {
            const data = await resp.json();
            const countEl = document.getElementById('approvalCount');
            if (countEl) {
                const pending = (data.approvals || []).filter(a => a.status === 'pending_approval').length;
                countEl.textContent = pending;
                countEl.style.display = pending > 0 ? 'inline' : 'none';
            }
        }
    } catch(e) {}
};

// ── Init conversations on load ──
document.addEventListener('DOMContentLoaded', () => {
    renderConversations();
});

// ══════════════════════════════════════════
// Approval Click → Preview Modal
// ══════════════════════════════════════════

async function viewApproval(approvalId) {
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const approval = await resp.json();

        const modal = document.getElementById('playbookModal');
        const title = document.getElementById('modalTitle');
        const playbook = document.getElementById('modalPlaybook');
        const meta = document.getElementById('modalMeta');
        const actions = document.getElementById('modalActions');

        title.textContent = approval.intent?.slice(0, 60) || 'Playbook Preview';
        playbook.contentEditable = false;
        playbook.textContent = approval.yaml_content || 'No YAML content';

        // Build meta info
        const riskClass = approval.risk_level || 'medium';
        const statusLabel = (approval.status || 'unknown').replace(/_/g, ' ');
        const blastSummary = approval.blast_radius?.summary || 'N/A';
        const validLabel = approval.validation?.valid ? '✅ Passed' : '❌ Issues found';
        const createdAt = approval.created_at?.slice(0, 19).replace('T', ' ') || '';
        const approvedBy = approval.approved_by || '';
        const approvedAt = approval.approved_at?.slice(0, 19).replace('T', ' ') || '';

        let metaHtml = `
            <div style="display:flex;flex-wrap:wrap;gap:16px;margin-top:12px;">
                <div><span style="color:var(--text-muted);font-size:11px;">STATUS</span><br>
                    <span class="playbook-row-status ${approval.status === 'pending_approval' ? 'pending' : approval.status}" style="display:inline-block;margin-top:4px;">${statusLabel}</span>
                </div>
                <div><span style="color:var(--text-muted);font-size:11px;">RISK</span><br>
                    <span class="risk-badge ${riskClass}" style="margin-top:4px;">${riskClass.toUpperCase()}</span>
                </div>
                <div><span style="color:var(--text-muted);font-size:11px;">BLAST RADIUS</span><br>
                    <span style="font-size:12px;color:var(--text-secondary);margin-top:4px;display:inline-block;">${blastSummary}</span>
                </div>
                <div><span style="color:var(--text-muted);font-size:11px;">VALIDATION</span><br>
                    <span style="font-size:12px;margin-top:4px;display:inline-block;">${validLabel}</span>
                </div>
            </div>
            <div style="margin-top:12px;font-size:11px;color:var(--text-muted);">
                Created: ${createdAt}
                ${approvedBy ? ` · Approved by: ${approvedBy} at ${approvedAt}` : ''}
            </div>`;

        // GitHub push info
        if (approval.github_push) {
            metaHtml += `<div style="margin-top:8px;font-size:11px;color:var(--success);">
                📦 Pushed to ${approval.github_push.repo} — commit ${approval.github_push.commit_sha?.slice(0, 8) || ''}
            </div>`;
        }

        // AAP execution info
        if (approval.aap_execution) {
            metaHtml += `<div style="margin-top:4px;font-size:11px;color:var(--success);">
                🚀 AAP job ${approval.aap_execution.job_id} — ${approval.aap_execution.status || 'launched'}
            </div>`;
        }

        meta.innerHTML = metaHtml;

        // Build action buttons based on status
        let actionsHtml = '';
        if (approval.status === 'pending_approval') {
            const hasIssues = !approval.validation?.valid;
            const approveClass = hasIssues ? 'btn btn-approve has-issues' : 'btn btn-approve';
            const approveLabel = hasIssues ? '⚠ Approve Anyway' : '✓ Approve & Deploy';

            actionsHtml = `
                <button class="${approveClass}" onclick="closeModal(); approvePlaybook('${approvalId}')">${approveLabel}</button>
                <button class="${hasIssues ? 'btn btn-edit suggested' : 'btn btn-edit'}" onclick="closeModal(); viewApprovalEdit('${approvalId}')">Edit</button>
                <button class="btn btn-reject" onclick="closeModal(); rejectPlaybook('${approvalId}')">Reject</button>`;
        } else if (approval.status === 'approved' && !approval.github_push) {
            actionsHtml = `<button class="btn btn-approve" onclick="closeModal(); approvePlaybook('${approvalId}')">Push to GitHub</button>`;
        } else {
            actionsHtml = `<button class="btn btn-edit" onclick="closeModal()">Close</button>`;
        }

        actions.innerHTML = actionsHtml;
        modal.classList.add('active');

    } catch (err) {
        console.error('Failed to load approval:', err);
    }
}

// ══════════════════════════════════════════
// Update Sidebar Approvals to use viewApproval
// ══════════════════════════════════════════

// Override loadApprovals to use viewApproval onclick
const _origLoadApprovals = loadApprovals;
loadApprovals = async function() {
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals`);
        if (!resp.ok) return;
        const data = await resp.json();

        const countEl = document.getElementById('approvalCount');
        const pending = (data.approvals || []).filter(a => a.status === 'pending_approval').length;
        if (countEl) {
            countEl.textContent = pending;
            countEl.style.display = pending > 0 ? 'inline' : 'none';
        }

        if (!data.approvals?.length) {
            approvalsList.innerHTML = '<div class="sidebar-empty">No pending approvals</div>';
            return;
        }

        approvalsList.innerHTML = data.approvals.slice(0, 10).map(a => {
            const cls = a.status === 'pending_approval' ? 'pending' :
                       a.status === 'approved' || a.status === 'executed' ? 'approved' : 'failed';
            return `
                <div class="sidebar-item ${cls}" onclick="viewApproval('${a.id}')">
                    <div class="sidebar-item-title">${(a.intent || a.playbook_id || '').slice(0, 40)}</div>
                    <div class="sidebar-item-meta">${(a.status || '').replace(/_/g, ' ')} · ${a.risk_level || 'medium'}</div>
                </div>`;
        }).join('');
    } catch (e) {}
};

// ══════════════════════════════════════════
// Playbooks Tab — Full History
// ══════════════════════════════════════════

async function loadPlaybooks() {
    const table = document.getElementById('playbooksTable');
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals`);
        if (!resp.ok) return;
        const data = await resp.json();

        if (!data.approvals?.length) {
            table.innerHTML = '<div class="table-empty">No playbooks generated yet. Start a conversation to create one.</div>';
            return;
        }

        table.innerHTML = `
            <div class="playbooks-header">
                <span class="ph-name">Playbook</span>
                <span class="ph-status">Status</span>
                <span class="ph-risk">Risk</span>
                <span class="ph-git">Git</span>
                <span class="ph-time">Time</span>
            </div>` +
            data.approvals.map(a => {
                const statusClass = a.status === 'pending_approval' ? 'pending' :
                                   a.status === 'approved' || a.status === 'executed' ? 'approved' :
                                   a.status === 'rejected' ? 'rejected' : 'expired';
                const statusLabel = (a.status || '').replace(/_/g, ' ');
                const gitIcon = a.github_push ? '✓' : '—';
                const gitClass = a.github_push ? 'color:var(--success)' : 'color:var(--text-muted)';
                const time = a.created_at?.slice(11, 16) || '';

                return `
                    <div class="playbook-row" onclick="viewApproval('${a.id}')">
                        <span class="playbook-row-name">${(a.intent || a.file_name || 'Untitled').slice(0, 55)}</span>
                        <span class="playbook-row-status ${statusClass}">${statusLabel}</span>
                        <span class="risk-badge ${a.risk_level || 'medium'}">${(a.risk_level || 'medium').toUpperCase()}</span>
                        <span style="font-size:13px;${gitClass};text-align:center;width:40px;">${gitIcon}</span>
                        <span class="playbook-row-time">${time}</span>
                    </div>`;
            }).join('');

    } catch (e) {
        table.innerHTML = '<div class="table-empty">Unable to load playbooks.</div>';
    }
}
    document.getElementById('modelSelect').addEventListener('change', async function() {
        const value = this.value;
        const provider = value === 'claude' || value === 'codex' ? value : 'ollama';
        const model = provider === 'ollama' ? value : undefined;
        try {
            await fetch(`${API_BASE}/ai/models/provider`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, model }),
            });
        } catch(e) { console.warn('Provider switch failed:', e); }
    });

async function viewApprovalEdit(approvalId) {
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}`);
        if (!resp.ok) return;
        const data = await resp.json();
        openEditModal(approvalId, data.yaml_content || '');
    } catch(e) { console.error(e); }
}