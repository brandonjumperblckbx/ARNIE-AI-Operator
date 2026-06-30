# RMCP AI Frontend - Complete Implementation

This package contains the complete AI-powered frontend for RMCP, including Python FastAPI service, C++ performance layer, and web UI.

## File Organization

Copy the files to your `rmcp/` directory as follows:

### Python AI Frontend
```
rmcp/python/ai-frontend/
├── main.py              ← FastAPI application with AI endpoints
├── claude_service.py    ← Claude API client wrapper
├── prompts.py           ← System prompts for different AI tasks
├── requirements.txt     ← Python dependencies
└── Dockerfile           ← Container image definition
```

### C++ Performance Layer
```
rmcp/cpp/performance/
├── include/
│   ├── event_processor.hpp      ← Event processor interface
│   ├── drift_detector.hpp       ← Drift detection interface
│   └── metrics_collector.hpp    ← Metrics collection interface
├── src/
│   ├── k8s_event_processor.cpp  ← Kubernetes event processor
│   ├── drift.cpp                ← Drift detection implementation
│   └── minio_event_processor.cpp  ← MinIO event processor (stub)
└── CMakeLists.txt               ← Build configuration
```

### Web UI
```
rmcp/ui/
├── index.html           ← Chat interface
└── app.js               ← Frontend JavaScript
```

### Schemas
```
rmcp/schemas/
└── ai-prompts.json      ← Prompt templates
```

## Quick Start

### 1. Install Python AI Frontend

```bash
cd rmcp/python/ai-frontend

# Set your Anthropic API key
export ANTHROPIC_API_KEY="your-api-key-here"

# Install dependencies
pip install -r requirements.txt

# Run the service
python main.py
```

The AI frontend will start on port 8081.

### 2. Test the API

```bash
# Create a policy from natural language
curl -X POST http://localhost:8081/ai/policy/create \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Give the monitoring team read-only access to database secrets in production",
    "auto_apply": false
  }'

# Analyze a policy
curl -X POST http://localhost:8081/ai/policy/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "principal": {"type": "ServiceAccount", "name": "api-backend"},
      "action": "Admin",
      "resource": {"type": "Secret"},
      "effect": "Allow"
    },
    "analysis_type": "security"
  }'
```

### 3. Use the Web UI

Open `rmcp/ui/index.html` in your browser (or serve it with a web server).

The UI connects to `http://localhost:8081` by default. You can:
- Chat with RMCP using natural language
- Create policies interactively
- Analyze existing policies
- Get drift explanations

### 4. Build C++ Performance Layer (Optional)

```bash
cd rmcp/cpp/performance

# Install dependencies
sudo apt-get install -y \
    cmake \
    build-essential \
    nlohmann-json3-dev \
    libssl-dev

# Build
mkdir build && cd build
cmake ..
make

# Run tests
./rmcp_performance_test
```

## API Endpoints

### AI-Powered Endpoints

**POST /ai/policy/create** - Convert natural language to semantic policy
```json
{
  "query": "Give the API service access to read database secrets",
  "auto_apply": false
}
```

**POST /ai/policy/analyze** - Analyze policy for security issues
```json
{
  "policy": { ... },
  "analysis_type": "security"
}
```

**POST /ai/drift/explain** - Get human-readable drift explanation
```json
{
  "drift_records": [ ... ],
  "intent": { ... }
}
```

**POST /ai/chat** - Conversational interface
```json
{
  "message": "Show me workflows in production namespace",
  "conversation_id": "optional-conversation-id"
}
```

**GET /ai/platforms/suggest** - Suggest target platforms
```
?resource_type=Secret&has_network_constraints=true
```

## Environment Variables

### AI Frontend
- `ANTHROPIC_API_KEY` - Your Anthropic API key (required)
- `RMCP_API_URL` - URL of RMCP core API (default: http://localhost:8080)

## Docker Deployment

### Build AI Frontend Image
```bash
cd rmcp/python/ai-frontend
docker build -t rmcp-ai-frontend:latest .
```

### Run with Docker
```bash
docker run -p 8081:8081 \
  -e ANTHROPIC_API_KEY="your-key" \
  -e RMCP_API_URL="http://rmcp-api:8080" \
  rmcp-ai-frontend:latest
```

## Kubernetes Deployment

Use the manifests in `rmcp/deployments/ai-frontend/`:

```bash
# Create secret with API key
kubectl create secret generic rmcp-ai-secrets \
  --from-literal=anthropic-api-key="your-key"

# Deploy
kubectl apply -f rmcp/deployments/ai-frontend/
```

## Integration with RMCP Core

The AI frontend communicates with RMCP core API:

```
┌─────────────────────┐
│   User / Web UI     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  AI Frontend :8081  │ ← Claude-powered NL interface
│  - Policy creation  │
│  - Drift analysis   │
│  - Chat interface   │
└──────────┬──────────┘
           │ HTTP
           ▼
┌─────────────────────┐
│  RMCP API :8080     │ ← Core policy engine
│  - State machine    │
│  - Translators      │
│  - Reconciliation   │
└─────────────────────┘
```

## Architecture Components

### Python Layer (AI Frontend)
- **main.py**: FastAPI endpoints for NL operations
- **claude_service.py**: Claude API wrapper with parsing logic
- **prompts.py**: System prompts optimized for RMCP tasks

### C++ Layer (Performance)
- **event_processor.hpp/cpp**: Real-time K8s/MinIO event streaming
- **drift_detector.hpp/cpp**: Sub-millisecond drift detection
- **metrics_collector.hpp**: Prometheus-compatible metrics

### Frontend (Web UI)
- **index.html**: Clean chat interface with quick actions
- **app.js**: API client and conversation management

## Example Workflows

### 1. Create Policy from Natural Language
```python
import requests

response = requests.post('http://localhost:8081/ai/policy/create', json={
    'query': 'Let the monitoring team list all pods in production',
    'auto_apply': True
})

workflow_id = response.json()['workflow_id']
print(f"Policy applied: {workflow_id}")
```

### 2. Analyze Existing Policy
```python
response = requests.post('http://localhost:8081/ai/policy/analyze', json={
    'policy': {
        'principal': {'type': 'User', 'name': 'admin'},
        'action': 'Admin',
        'resource': {'type': 'Secret', 'namespace': 'production'},
        'effect': 'Allow'
    },
    'analysis_type': 'security'
})

analysis = response.json()
print(f"Risk score: {analysis['risk_score']}")
for finding in analysis['findings']:
    print(f"- {finding['title']}: {finding['description']}")
```

### 3. Interactive Chat
```python
response = requests.post('http://localhost:8081/ai/chat', json={
    'message': 'What workflows are currently running?'
})

print(response.json()['response'])
```

## Development

### Running Locally
```bash
# Terminal 1: RMCP Core API (if you have it running)
cd rmcp/python/api
python main.py

# Terminal 2: AI Frontend
cd rmcp/python/ai-frontend
export ANTHROPIC_API_KEY="your-key"
python main.py

# Terminal 3: Serve UI (optional)
cd rmcp/ui
python -m http.server 8000
# Open http://localhost:8000
```

### Testing
```bash
# Test policy creation
pytest tests/test_policy_creation.py

# Test drift detection
pytest tests/test_drift_analysis.py
```

## Troubleshooting

**Issue**: "ANTHROPIC_API_KEY not set"
- Solution: `export ANTHROPIC_API_KEY="your-key"`

**Issue**: "Connection refused to RMCP API"
- Solution: Make sure RMCP core API is running on port 8080
- Or set: `export RMCP_API_URL="http://your-api:8080"`

**Issue**: "JSON parse error from Claude"
- Solution: Check prompts.py - Claude should return pure JSON
- Enable verbose logging to see raw responses

**Issue**: C++ build fails with "nlohmann/json not found"
- Solution: `sudo apt-get install nlohmann-json3-dev`

## Next Steps

1. **Deploy to OpenShift**: Use the deployment YAMLs in `deployments/ai-frontend/`
2. **Add Authentication**: Integrate with Keycloak SSO
3. **Connect C++ Layer**: Wire up event processor to Rust state machine
4. **Add More Translators**: Extend for AWS IAM, Azure RBAC, etc.
5. **Build Dashboard**: Add workflow visualization UI

## Support

- Documentation: `/docs` (FastAPI auto-generated)
- Health check: `GET /health`
- Metrics: `GET /metrics` (Prometheus format)

## License

BLCKBX Internal - See LICENSE file
