/**
 * AdaptiveShield RAG - Backend API Client
 * Configured via VITE_API_BASE_URL environment variable.
 */

const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '');

async function handleResponse(response) {
  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const data = await response.json();
      if (data && data.detail) {
        errorDetail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      }
    } catch {
      // Ignore JSON parse errors for non-JSON responses
    }
    throw new Error(errorDetail);
  }
  return response.json();
}

/**
 * Fetch current threat state and velocity metrics
 */
export async function getThreatState() {
  const res = await fetch(`${API_BASE}/api/v1/security/threat-state`);
  return handleResponse(res);
}

/**
 * Fetch recent ingested documents
 */
export async function getRecentDocuments(limit = 25) {
  const res = await fetch(`${API_BASE}/api/v1/documents?limit=${limit}`);
  return handleResponse(res);
}

/**
 * Fetch segregated knowledge store statistics
 */
export async function getKnowledgeStats() {
  const res = await fetch(`${API_BASE}/api/v1/knowledge/stats`);
  return handleResponse(res);
}

/**
 * Launch synthetic knowledge stream simulation
 */
export async function startSimulation({ mode = 'mixed', document_count = 10, attack_ratio = null, delay_ms = 0 }) {
  const payload = { mode, document_count, delay_ms };
  if (attack_ratio !== null && attack_ratio !== undefined) {
    payload.attack_ratio = attack_ratio;
  }
  const res = await fetch(`${API_BASE}/api/v1/simulation/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return handleResponse(res);
}

/**
 * Fetch simulation running status
 */
export async function getSimulationStatus() {
  const res = await fetch(`${API_BASE}/api/v1/simulation/status`);
  return handleResponse(res);
}

/**
 * Query trust-aware RAG pipeline
 */
export async function queryRAG(query, top_k = 5) {
  const res = await fetch(`${API_BASE}/api/v1/rag/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, top_k }),
  });
  return handleResponse(res);
}

/**
 * Direct trust-aware retrieval (preview evidence)
 */
export async function retrieveTrusted(query, top_k = 5) {
  const res = await fetch(`${API_BASE}/api/v1/rag/retrieve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, top_k }),
  });
  return handleResponse(res);
}
