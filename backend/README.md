# AdaptiveShield RAG - Backend

FastAPI backend service providing document ingestion, security signal analysis, adaptive threat monitoring, security-gated vector storage, trust-aware RAG retrieval, and live stream attack simulation for the AdaptiveShield RAG system.

> **Status:** Live Stream & Attack Simulator (Step 7 Complete). A synthetic attack simulator generates controlled streams (`normal`, `attack`, `mixed`) that flow directly through the live defense pipeline: Ingestion $\to$ Security Signal Analysis $\to$ Composite Risk Assessment $\to$ Assessment History Recording $\to$ Gated Vector Storage $\to$ Threat-State Monitoring. Quarantined and blocked documents are strictly isolated, and only verified safe knowledge enters the trusted vector store for RAG queries.

---

## Architecture Flow

```
ATTACK SIMULATOR (normal / attack / mixed)
        ↓
    INGESTION (SQLite)
        ↓
SECURITY ANALYSIS & COMPOSITE RISK SCORING
        ↓
      DECISION ──→ ASSESSMENT HISTORY (SQLite)
     /   |   \               ↓
  SAFE   |   BLOCK       ATTACK VELOCITY
   ↓     ↓   (Rejected)      ↓
Trusted  Quarantine      THREAT STATE
Store    Store           (NORMAL / ELEVATED / HIGH / CRITICAL)
   ↓
TRUST-AWARE RETRIEVER (Queries ONLY Trusted Store)
   ↓
CONTEXT BUILDER
   ↓
LLM GENERATION (with graceful unconfigured fallback)
   ↓
ANSWER + CITED SOURCES
```

---

## Getting Started

### 1. Prerequisites

- Python 3.11+
- Virtual environment tool (`venv`)

### 2. Setup Virtual Environment

From the project root or the `backend/` directory:

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment:

- **Windows (PowerShell):**
  ```powershell
  .venv\Scripts\Activate.ps1
  ```
- **Linux / macOS:**
  ```bash
  source .venv/bin/activate
  ```

### 3. Install Dependencies

Install backend requirements:

```bash
pip install -r requirements.txt
```

### 4. Running the Backend Server

Start the development server with Uvicorn:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Once running, access:
- **Root API status:** [http://localhost:8000/](http://localhost:8000/)
- **Health check:** [http://localhost:8000/health](http://localhost:8000/health)
- **Interactive OpenAPI docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API Reference

### 1. Document Ingestion API (`/api/v1/documents`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/documents` | Ingest a new document (initial status `PENDING`) |
| `GET` | `/api/v1/documents` | Retrieve recent documents (supports `limit`, `offset`) |
| `GET` | `/api/v1/documents/{id}` | Retrieve a document by unique ID |
| `PATCH`| `/api/v1/documents/{id}/status` | Update document status (`PENDING`, `SAFE`, `QUARANTINE`, `BLOCKED`) |

---

### 2. Security Analysis & Threat State API (`/api/v1/security`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/security/analyze/{document_id}` | Runs multi-signal heuristic analysis on an ingested document |
| `POST` | `/api/v1/security/assess/{document_id}` | Evaluates composite risk score and triage decision (`SAFE`, `QUARANTINE`, `BLOCK`) |
| `GET` | `/api/v1/security/threat-state` | Returns rolling attack velocity, block rate, and global threat state (`NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL`) |

---

### 3. Security-Gated Knowledge Storage API (`/api/v1/knowledge`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/knowledge/index/{document_id}` | Evaluates triage and indexes into segregated vector store (`SAFE` → Trusted, `QUARANTINE` → Quarantine, `BLOCK` → Rejected) |
| `GET` | `/api/v1/knowledge/{document_id}` | Looks up indexed document across vector collections |
| `GET` | `/api/v1/knowledge/stats` | Returns counts and metadata for trusted and quarantined collections |

---

### 4. Trust-Aware Retrieval & Basic RAG API (`/api/v1/rag`)

Base path: `/api/v1/rag`

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/rag/retrieve` | Trust-aware vector search querying **ONLY** the trusted collection |
| `POST` | `/api/v1/rag/query` | Complete RAG workflow: retrieve trusted context → build prompt → generate answer |

#### Critical Security Invariant

> **CRITICAL:** The retrieval layer is strictly bound to `trusted_collection`. It **NEVER** queries or searches:
> - The quarantine collection
> - Blocked documents
> - Raw SQLite tables
> - Any unverified or pending knowledge

---

### 5. Attack Simulator API (`/api/v1/simulation`)

Base path: `/api/v1/simulation`

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/simulation/start` | Launch a controlled synthetic knowledge stream (`normal`, `attack`, `mixed`) |
| `GET` | `/api/v1/simulation/status` | Retrieve current simulator running status and latest execution summary |

#### Simulation Modes

- **`normal`:** Simulates typical stream conditions with predominantly benign documents (`SAFE`). Attack velocity remains low, keeping threat state at `NORMAL` or `ELEVATED`.
- **`attack`:** Simulates an active adversarial campaign with prompt injections, instruction overrides, and untrusted sources. High block and quarantine rates trigger `HIGH` or `CRITICAL` threat states.
- **`mixed`:** Balanced stream containing both benign operational policies and adversarial probes.

#### Simulation Example

**Request:**

```bash
curl -X POST http://localhost:8000/api/v1/simulation/start \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "attack",
    "document_count": 10,
    "attack_ratio": 0.8,
    "delay_ms": 0
  }'
```

**Response (`200 OK`):**

```json
{
  "simulation_id": "7f8b9e2c-3d4a-4f5b-b91c-2e3f4a5b6c7d",
  "mode": "attack",
  "total_generated": 10,
  "safe_count": 2,
  "quarantine_count": 4,
  "block_count": 4,
  "average_risk_score": 0.584,
  "current_threat_state": "CRITICAL",
  "attack_velocity": 0.8000,
  "duration_ms": 235.40,
  "documents": [ ... ]
}
```

---

## Configuration

Settings are managed via environment variables or a `.env` file:

```env
# Database & Vector Storage
SQLITE_DB_PATH=data/adaptiveshield.db
VECTOR_DB_DIR=data/vector_store
EMBEDDING_MODEL_NAME=sentence-transformers/all-MiniLM-L6-v2
TRUSTED_COLLECTION_NAME=trusted_knowledge
QUARANTINE_COLLECTION_NAME=quarantined_knowledge

# Security Triage Thresholds
RISK_THRESHOLD_QUARANTINE=0.40
RISK_THRESHOLD_BLOCK=0.70

# Threat State Window
ATTACK_VELOCITY_WINDOW_SECONDS=300

# LLM & RAG Configuration (Optional)
LLM_PROVIDER=openai
LLM_API_KEY=your-api-key-here
LLM_MODEL=gpt-4o-mini
```

---

## Running Tests

Run the complete test suite (81 tests across ingestion, security heuristics, composite risk, threat velocity, vector segregation, trust-aware RAG, and attack simulation):

```bash
pytest -v backend
```
