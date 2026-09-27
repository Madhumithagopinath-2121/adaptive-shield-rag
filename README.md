# AdaptiveShield RAG

> **Real-Time Poisoning Defense for Dynamic RAG Streams**

AdaptiveShield RAG is a research-oriented security framework designed to protect continuously updating Retrieval-Augmented Generation (RAG) pipelines from corpus poisoning and indirect prompt injection attacks.

---

## 1. Problem Statement

Standard RAG architectures assume knowledge corpora are relatively static and pre-curated. In production and real-time enterprise settings, however, knowledge streams update continuously from dynamic sources (e.g., live feeds, support tickets, internal wikis, automated web syncs, and user submissions).

This operational reality opens a critical attack surface:
- **Corpus Poisoning:** Malicious or compromised data injected into the knowledge stream degrades retrieval quality, introduces factual falsifications, or embeds backdoor behaviors.
- **Indirect Prompt Injection:** Adversarial documents crafted to manipulate the downstream LLM when retrieved, bypassing perimeter system prompts and inducing unauthorized actions or data exfiltration.

Existing post-retrieval guardrails inspect queries and generated answers, but frequently overlook the real-time ingestion boundary, allowing tainted content to persist inside vector stores.

---

## 2. Project Goal

The primary goal of AdaptiveShield RAG is to investigate and prototype an **adaptive security layer** positioned directly between live ingestion streams and the vector indexing layer. By triaging incoming chunks through multi-signal risk scoring, the system prevents adversarial payloads from contaminating trusted vector stores and provides trust-aware retrieval for downstream LLMs.

---

## 3. Proposed Architecture

```text
Live Knowledge Stream
        ↓
    Ingestion
        ↓
 Security Engine
        ↓
  Risk Scoring
        ↓
SAFE / QUARANTINE / BLOCK
        ↓
 Trusted Vector Store
        ↓
 Trust-Aware Retrieval
        ↓
       LLM
        ↓
 Answer + Sources
```

### Ingestion & Security Pipeline Stages:
1. **Live Knowledge Stream:** Asynchronous event stream or document batch feeder simulating dynamic ingestion.
2. **Ingestion & Normalization:** Document parsing, chunking, and metadata tagging (source provenance, timestamp, author attribution).
3. **Security Engine:** Multi-layer inspection evaluating structural anomalies, injection patterns, and semantic deviation.
4. **Risk Scoring:** Calculation of a normalized risk score (\(0.0 \le \text{Risk} \le 1.0\)) based on heuristic signals and semantic checks.
5. **Triage Decision:**
   - **SAFE:** Chunk passed to the trusted vector store.
   - **QUARANTINE:** Suspicious chunk isolated in a quarantined index for manual review or secondary verification.
   - **BLOCK:** Discarded, logged, and alerted to security telemetry.
6. **Trusted Vector Store:** Persistent vector index containing only verified, safe document embeddings.
7. **Trust-Aware Retrieval:** Retrieval engine incorporating trust metadata and similarity metrics to select context for generation.
8. **LLM Generation:** Downstream language model producing the final answer, strictly citing verified sources and associated trust levels.

---

## 4. Planned Technology Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend** | Python 3.11+, FastAPI, Pydantic | High performance async API handling streaming ingestion and query endpoints. |
| **Frontend** | React (Vite, TypeScript, TailwindCSS) | Real-time monitoring dashboard for knowledge streams, triage stats, and query playground. |
| **Embeddings** | Sentence Transformers (`all-MiniLM-L6-v2`) | Local, deterministic embedding generation without third-party API latency. |
| **Vector Store** | ChromaDB (Local / Embedded) | Lightweight, file-backed local vector store optimal for rapid prototyping. |
| **Relational DB** | SQLite | Zero-configuration local database for document metadata, audit logs, and quarantine records. |
| **Containerization** | Docker & Docker Compose | Multi-container setup ensuring cross-platform reproducibility for research benchmarks. |
| **Version Control** | Git & GitHub | Branching workflows, issue tracking, and experiment versioning. |

---

## 5. Project Directory Structure

```text
adaptive-shield-rag/
├── docs/                     # Architecture, threat model, and research notes
│   ├── architecture.md       # Detailed technical design and data flow
│   └── threat-model.md       # Attack vectors, assumptions, and defenses
├── backend/                  # Python FastAPI service (planned)
├── frontend/                 # React UI application (planned)
├── data/                     # Local storage for SQLite DB and vector index (ignored in git)
├── .env.example              # Template configuration variables
├── .gitignore                # Git ignore rules for Python, Node, databases, and secrets
└── README.md                 # Project overview and setup documentation
```

---

## 6. Setup & Verification (Foundational Phase)

At this stage, only repository foundations and documentation are initialized. Application code has not yet been written.

### Prerequisites
- Git installed on your local machine
- Python 3.11+ (for upcoming backend implementation)
- Node.js 18+ & npm (for upcoming frontend implementation)

### Verify Repository Setup
Check that the foundational files are present:

```bash
# Verify directory structure
git status
ls -la
```

---

## 7. Research Framing & Scope Note

AdaptiveShield RAG is developed as an empirical defense-in-depth prototype. Defensive performance, latency overhead, and bypass resilience will be evaluated using standard security benchmarks and synthetic poisoning datasets. No claims of novelty or complete infallibility are made without rigorous experimental evidence and empirical validation.
