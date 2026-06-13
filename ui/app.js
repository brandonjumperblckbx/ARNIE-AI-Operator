/**
 * ARNIE AI — Chat Interface
 * Ansible Remediation & Navigation Intelligence Engine
 * Built on RMCP by BLCKBX
 */

const API_BASE = '';
let conversationId = null;
let isGenerating = false;

// ── DOM refs ──
const chatInput = document.getElementById('chatInput');
const sendBtn = document.getElementById('sendBtn');
const messagesEl = document.getElementById('messages');
const welcomeScreen = document.getElementById('welcomeScreen');
const approvalsList = document.getElementById('approvalsList');
const jobsList = document.getElementById('jobsList');
const githubStatus = document.getElementById('githubStatus');
const aapStatus = document.getElementById('aapStatus');

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
    chatInput.addEventListener('keydown', handleKeyDown);
    chatInput.addEventListener('input', autoResize);
    checkConnections();
    loadApprovals();
    setInterval(checkConnections, 30000);
    setInterval(loadApprovals, 15000);
});

function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
}

function autoResize() {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 150) + 'px';
}

// ── Send Message ──
async function sendMessage() {
    const message = chatInput.value.trim();
    if (!message || isGenerating) return;

    isGenerating = true;
    sendBtn.disabled = true;

    // Hide welcome, show messages
    welcomeScreen.style.display = 'none';
    messagesEl.classList.add('active');

    // Add user message
    appendMessage('user', message);
    chatInput.value = '';
    chatInput.style.height = 'auto';

    // Show typing
    showTyping();

    try {
        const resp = await fetch(`${API_BASE}/ai/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                conversation_id: conversationId,
                context: {},
            }),
        });

        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        conversationId = data.conversation_id;
        hideTyping();

        // Render response
        if (data.playbook) {
            appendPlaybookMessage(data);
        } else {
            appendMessage('agent', data.response);
        }

        // Refresh approvals
        loadApprovals();

    } catch (err) {
        hideTyping();
        appendMessage('agent',
            `Connection error: ${err.message}. Make sure the ARNIE backend is running on port 8082.`
        );
    }

    isGenerating = false;
    sendBtn.disabled = false;
    chatInput.focus();
}

// ── Welcome Card Prompts ──
function usePrompt(text) {
    chatInput.value = text;
    chatInput.focus();
    autoResize();
}

// ── Message Rendering ──
function appendMessage(role, content) {
    const el = document.createElement('div');
    el.className = `message ${role}`;

    const avatar = role === 'user' ? 'U' : 'A';
    const avatarClass = role === 'user' ? 'user-avatar' : 'agent-avatar';
    const sender = role === 'user' ? 'You' : 'ARNIE';

    el.innerHTML = `
        <div class="message-header">
            <div class="message-avatar ${avatarClass}">${avatar}</div>
            <div class="message-sender">${sender}</div>
        </div>
        <div class="message-body">${formatContent(content)}</div>
    `;

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
            <div class="message-avatar agent-avatar">A</div>
            <div class="message-sender">ARNIE</div>
        </div>
        <div class="message-body">
            <p>${formatContent(data.response.split('```')[0])}</p>
            <div class="playbook-block">
                <div class="playbook-block-header">
                    <span class="playbook-block-title">${pb.file_name || 'playbook.yml'}</span>
                    <div class="playbook-block-actions">
                        <span class="risk-badge ${riskClass}">${riskClass.toUpperCase()}</span>
                    </div>
                </div>
                <div class="playbook-block-body">
                    <pre><code>${escapeHtml(pb.yaml_content)}</code></pre>
                </div>
            </div>
            <div style="font-size:13px;color:var(--text-secondary);margin:8px 0;">
                <strong>Blast Radius:</strong> ${blastSummary} &nbsp;|&nbsp;
                <strong>Validation:</strong> ${validation}
            </div>
            <div class="approval-bar">
                <button class="btn btn-approve" onclick="approvePlaybook('${pb.approval_id}')">✓ Approve & Deploy</button>
                <button class="btn btn-edit" onclick="openEditModal('${pb.approval_id}', ${JSON.stringify(JSON.stringify(pb.yaml_content))})">Edit</button>
                <button class="btn btn-reject" onclick="rejectPlaybook('${pb.approval_id}')">Reject</button>
            </div>
        </div>
    `;

    messagesEl.appendChild(el);
    scrollToBottom();
}

// ── Approval Actions ──
async function approvePlaybook(approvalId) {
    try {
        appendMessage('agent', '⏳ Approving playbook, pushing to GitHub, and launching AAP job...');
        showTyping();

        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ actor: 'operator', reason: 'Approved via ARNIE UI' }),
        });

        hideTyping();
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        let statusMsg = '✅ **Playbook approved!**\n\n';
        if (data.github) {
            statusMsg += `📦 **GitHub:** Committed \`${data.github.commit_sha?.slice(0, 8)}\` to \`${data.github.repo}\`\n`;
        }
        if (data.aap) {
            statusMsg += `🚀 **AAP:** Job \`${data.aap.job_id}\` launched — status: ${data.aap.status}\n`;
        }

        appendMessage('agent', statusMsg);
        loadApprovals();

    } catch (err) {
        hideTyping();
        appendMessage('agent', `❌ Approval failed: ${err.message}`);
    }
}

async function rejectPlaybook(approvalId) {
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ actor: 'operator', reason: 'Rejected via ARNIE UI' }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        appendMessage('agent', '🚫 Playbook rejected. No changes were made.');
        loadApprovals();

    } catch (err) {
        appendMessage('agent', `❌ Rejection failed: ${err.message}`);
    }
}

function openEditModal(approvalId, yamlContent) {
    const modal = document.getElementById('playbookModal');
    const title = document.getElementById('modalTitle');
    const playbook = document.getElementById('modalPlaybook');
    const actions = document.getElementById('modalActions');

    title.textContent = 'Edit Playbook';

    // Make it editable
    playbook.contentEditable = true;
    playbook.textContent = yamlContent;
    playbook.style.outline = 'none';
    playbook.style.minHeight = '300px';

    actions.innerHTML = `
        <button class="btn btn-reject" onclick="closeModal()">Cancel</button>
        <button class="btn btn-approve" onclick="saveEdit('${approvalId}')">Save & Re-validate</button>
    `;

    modal.classList.add('active');
}

async function saveEdit(approvalId) {
    const playbook = document.getElementById('modalPlaybook');
    const newYaml = playbook.textContent;

    try {
        const resp = await fetch(`${API_BASE}/ai/approvals/${approvalId}/edit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ yaml_content: newYaml }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        closeModal();
        appendMessage('agent',
            `✏️ Playbook updated and re-validated. ` +
            `Validation: ${data.validation?.valid ? '✅ Passed' : '❌ Issues found'}`
        );

    } catch (err) {
        appendMessage('agent', `❌ Edit failed: ${err.message}`);
    }
}

function closeModal() {
    document.getElementById('playbookModal').classList.remove('active');
}

// ── Sidebar ──
async function loadApprovals() {
    try {
        const resp = await fetch(`${API_BASE}/ai/approvals`);
        if (!resp.ok) return;
        const data = await resp.json();

        if (!data.approvals || data.approvals.length === 0) {
            approvalsList.innerHTML = '<div class="sidebar-empty">No pending approvals</div>';
            return;
        }

        approvalsList.innerHTML = data.approvals.slice(0, 10).map(a => {
            const statusClass = a.status === 'pending_approval' ? 'pending' :
                               a.status === 'approved' ? 'approved' :
                               a.status === 'executed' ? 'approved' : 'failed';
            const statusLabel = a.status.replace('_', ' ');
            return `
                <div class="sidebar-item ${statusClass}" onclick="openEditModal('${a.id}', ${JSON.stringify(JSON.stringify(a.yaml_content || ''))})">
                    <div class="sidebar-item-title">${a.intent?.slice(0, 40) || a.playbook_id}</div>
                    <div class="sidebar-item-meta">${statusLabel} • ${a.risk_level || 'medium'}</div>
                </div>
            `;
        }).join('');

    } catch (err) {
        // Silent fail — sidebar is supplementary
    }
}

// ── Connection Status ──
async function checkConnections() {
    // GitHub
    try {
        const resp = await fetch(`${API_BASE}/git/status`);
        if (resp.ok) {
            const data = await resp.json();
            const dot = githubStatus.querySelector('.status-dot');
            dot.className = `status-dot ${data.connected ? 'online' : 'offline'}`;
        }
    } catch (e) {}

    // AAP
    try {
        const resp = await fetch(`${API_BASE}/aap/status`);
        if (resp.ok) {
            const data = await resp.json();
            const dot = aapStatus.querySelector('.status-dot');
            dot.className = `status-dot ${data.connected ? 'online' : 'offline'}`;
        }
    } catch (e) {}
}

// ── Helpers ──
function showTyping() {
    let typing = document.querySelector('.typing');
    if (!typing) {
        typing = document.createElement('div');
        typing.className = 'typing';
        typing.innerHTML = `
            <div class="message-header">
                <div class="message-avatar agent-avatar">A</div>
                <div class="message-sender">ARNIE</div>
            </div>
            <div class="typing-dots">
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
            </div>
        `;
        messagesEl.appendChild(typing);
    }
    typing.classList.add('active');
    scrollToBottom();
}

function hideTyping() {
    const typing = document.querySelector('.typing');
    if (typing) typing.remove();
}

function scrollToBottom() {
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function escapeHtml(text) {
    const el = document.createElement('div');
    el.textContent = text;
    return el.innerHTML;
}

function formatContent(text) {
    if (!text) return '';

    // Code blocks
    text = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
        return `<pre><code>${escapeHtml(code.trim())}</code></pre>`;
    });

    // Inline code
    text = text.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

    // Line breaks
    text = text.replace(/\n/g, '<br>');

    return text;
}
