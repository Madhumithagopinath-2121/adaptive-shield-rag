# AdaptiveShield RAG - Backend

FastAPI backend service providing document ingestion, security signal analysis, and composite risk triage for the AdaptiveShield RAG system.

> **Status:** Composite Risk Scoring & Security Decision Engine (Step 3B). Ingested documents (initial status `PENDING`) can be evaluated across multi-signal heuristics, yielding an explainable composite risk score and triage decision (`SAFE`, `QUARANTINE`, `BLOCK`). Embeddings, vector storage, and automated state transitions are not yet active.

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

Install the foundational backend requirements:

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

## Document Ingestion API

Base path: `/api/v1/documents`

### Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/documents` | Ingest a new document (initial status `PENDING`) |
| `GET` | `/api/v1/documents` | Retrieve recent documents (supports `limit`, `offset`) |
| `GET` | `/api/v1/documents/{id}` | Retrieve a document by unique ID |
| `PATCH`| `/api/v1/documents/{id}/status` | Update document status (`PENDING`, `SAFE`, `QUARANTINE`, `BLOCKED`) |

---

## Security Signal Analysis & Decision API

Base path: `/api/v1/security`

### Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/security/analyze/{document_id}` | Runs multi-signal heuristic analysis on an ingested document (intermediate signals only) |
| `POST` | `/api/v1/security/assess/{document_id}` | Assesses composite risk score and evaluates triage decision (`SAFE`, `QUARANTINE`, `BLOCK`) |

### Difference Between Signals and Decisions

- **Security Signals (`/analyze`):** Transparent intermediate metrics representing specific heuristic observations (`injection_score`, `source_risk_score`, `content_anomaly_score`). They do not compute composite risk or apply access control policies.
- **Security Decisions (`/assess`):** Evaluates all signals through a normalized composite scoring model and compares the score against configurable thresholds to produce an operational triage outcome (`SAFE`, `QUARANTINE`, or `BLOCK`). Assessment does **not** mutate the document's stored status.

### Assessment Example

**Request:**

```bash
curl -X POST http://localhost:8000/api/v1/security/assess/e6a1005f-fc8c-4a57-b08e-8a032d84950d
```

**Response (`200 OK`):**

```json
{
    "document_id": "e6a1005f-fc8c-4a57-b08e-8a032d84950d",
    "injection_score": 0.0,
    "source_risk_score": 0.40,
    "content_anomaly_score": 0.0,
    "risk_score": 0.10,
    "decision": "SAFE",
    "signals": [
        "source_medium_trust"
    ],
    "explanations": [
        "Source type 'wiki' is categorized as medium-trust.",
        "Composite risk score (0.10) remained below the QUARANTINE threshold (0.40). Decision: SAFE."
    ]
}
```

---

## Composite Risk Scoring & Triage Logic

### Scoring Formula

The prototype uses a transparent weighted scoring model:

| Signal | Planned Weight | MVP Active Weight | Role |
| :--- | :--- | :--- | :--- |
| **Prompt Injection** | 0.40 | 0.40 | Detects instruction overrides, system directives, and prompt leakage |
| **Source Provenance** | 0.20 | 0.20 | Assesses risk based on source type and provenance metadata |
| **Content Anomaly** | 0.20 | 0.20 | Flags control tokens, excessive repetition, and imperative density |
| **Reserved Signals** | 0.20 | *(unassigned)* | Reserved for contradiction and attack-velocity signals in streaming phase |

> **Note on MVP Normalization:** The current MVP uses three deterministic security signals. Contradiction and attack-velocity signals are planned for the adaptive streaming phase.

Active signals are normalized over the active weight sum ($0.40 + 0.20 + 0.20 = 0.80$):

$$\text{risk\_score} = \frac{0.40 \cdot \text{injection\_score} + 0.20 \cdot \text{source\_risk\_score} + 0.20 \cdot \text{content\_anomaly\_score}}{0.80}$$

The resulting `risk_score` is strictly bounded between `0.0` (zero observed risk) and `1.0` (maximal threat indicators).

### Decision Thresholds

Triage outcomes are mapped via configurable environment variables:

- **SAFE (`risk_score < 0.40`):** Minimal indicators. Eligible for future ingestion into trusted vector stores.
- **QUARANTINE (`0.40 <= risk_score < 0.70`):** Elevated risk or suspicious source/instruction combination. Isolated for secondary analysis or manual review.
- **BLOCK (`risk_score >= 0.70`):** High composite risk. Document presents significant injection patterns or structural anomalies.

*Configuration variables (`.env.example` / `config.py`):*
```env
RISK_THRESHOLD_QUARANTINE=0.40
RISK_THRESHOLD_BLOCK=0.70
```

*Statement:* These threshold boundaries are prototype heuristic parameters and do not represent scientifically optimal security barriers.

---

## Limitations

- The decision engine relies on heuristic signal weights and static thresholds. It does not completely prevent poisoning, sophisticated semantic attacks, or zero-day prompt injection evasions.
- Low-trust sources contribute risk but do not independently trigger a `BLOCK` without accompanying content anomalies or injection markers.
- Multi-layer defense-in-depth, semantic contradiction detection, and adaptive rate-limiting are planned for future development phases.

---

## Running Tests

Run the test suite with pytest from the `backend/` directory:

```bash
pytest
```
