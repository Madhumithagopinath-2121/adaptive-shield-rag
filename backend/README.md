# AdaptiveShield RAG - Backend

FastAPI backend service providing document ingestion, security signal analysis, adaptive threat monitoring, security-gated vector storage, and trust-aware RAG retrieval for the AdaptiveShield RAG system.

> **Status:** Trust-Aware Retrieval & Basic RAG (Step 6 Complete). Ingested documents undergo multi-signal security triage (`SAFE`, `QUARANTINE`, `BLOCK`). Verified `SAFE` documents are segregated into a trusted ChromaDB collection, while `QUARANTINE` documents are placed in an isolated quarantine collection, and `BLOCK` documents are strictly rejected. The RAG retrieval pipeline queries **ONLY** the trusted collection, ensuring quarantined or poisoned content never influences downstream LLMs.

---

## Architecture Flow

```
LIVE KNOWLEDGE STREAM
        ↓
    INGESTION (SQLite)
        ↓
SECURITY ANALYSIS & COMPOSITE RISK SCORING
        ↓
      DECISION
     /   |   \
  SAFE   |   BLOCK (Strictly Rejected)
   ↓     ↓
Trusted  Quarantine
Collection  Collection
   ↓
TRUST-AWARE RETRIEVER (Queries ONLY Trusted Collection)
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

#### Retrieval Example

**Request:**

```bash
curl -X POST http://localhost:8000/api/v1/rag/retrieve \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is the corporate MFA policy?",
    "top_k": 3
  }'
```

**Response (`200 OK`):**

```json
{
  "query": "What is the corporate MFA policy?",
  "retrieved_count": 1,
  "results": [
    {
      "document_id": "c1f7b8d2-...",
      "title": "Corporate Multi-Factor Authentication Policy",
      "content": "All company personnel must authenticate using FIDO2 hardware security keys...",
      "source": "https://infosec.corp.internal/mfa-policy",
      "source_type": "internal",
      "timestamp": "2026-09-28T18:00:00Z",
      "decision": "SAFE",
      "risk_score": 0.05,
      "distance": 0.1245
    }
  ]
}
```

#### RAG Query Example

**Request:**

```bash
curl -X POST http://localhost:8000/api/v1/rag/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the MFA requirements for employees?"
  }'
```

**Response (`200 OK`):**

```json
{
  "query": "What are the MFA requirements for employees?",
  "answer": "LLM is not configured. Here are the trusted retrieved sources:\n\n[1] Corporate Multi-Factor Authentication Policy (Source: https://infosec.corp.internal/mfa-policy)\nAll company personnel must authenticate using FIDO2 hardware security keys...",
  "sources": [
    {
      "document_id": "c1f7b8d2-...",
      "title": "Corporate Multi-Factor Authentication Policy",
      "content": "All company personnel must authenticate using FIDO2 hardware security keys...",
      "source": "https://infosec.corp.internal/mfa-policy",
      "source_type": "internal",
      "timestamp": "2026-09-28T18:00:00Z",
      "decision": "SAFE",
      "risk_score": 0.05,
      "distance": 0.1245
    }
  ],
  "retrieved_count": 1
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

If `LLM_API_KEY` is omitted or empty, the RAG query pipeline operates in zero-dependency fallback mode, returning trusted citations and extracted knowledge without errors.

---

## Running Tests

Run the complete test suite (71 tests across ingestion, security heuristics, composite risk, threat velocity, vector segregation, and trust-aware RAG):

```bash
pytest -v backend
```
