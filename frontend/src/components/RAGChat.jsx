import React, { useState } from 'react';
import { MessageSquare, Send, ShieldCheck, AlertCircle, Loader2 } from 'lucide-react';
import { queryRAG } from '../services/api';

export default function RAGChat() {
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [response, setResponse] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const trimmed = query.trim();
    if (!trimmed || isLoading) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await queryRAG(trimmed);
      setResponse(data);
    } catch (err) {
      setError(err.message || 'Failed to query RAG pipeline');
    } finally {
      setIsLoading(false);
    }
  };

  // Only display safe / trusted sources, strictly exclude quarantine or blocked documents
  const trustedSources = (response?.sources || []).filter(
    (s) => s.decision === 'SAFE' && s.decision !== 'QUARANTINE' && s.decision !== 'BLOCK'
  );

  return (
    <div className="card">
      <div className="card-title">
        <MessageSquare size={16} color="var(--accent)" />
        Trust-Aware RAG Query & Verification
      </div>
      <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px' }}>
        Query verified enterprise knowledge. The trust-aware retriever exclusively accesses the verified safe knowledge store, strictly excluding quarantined and blocked payloads.
      </div>

      <form onSubmit={handleSubmit} className="rag-chat-box">
        <div className="chat-input-row">
          <input
            type="text"
            className="chat-input"
            placeholder="Ask a question (e.g., 'What is the corporate MFA policy?')..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !query.trim()}
            className="btn btn-primary"
          >
            {isLoading ? (
              <>
                <Loader2 size={16} className="spin" />
                Querying...
              </>
            ) : (
              <>
                <Send size={16} />
                ASK RAG
              </>
            )}
          </button>
        </div>

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--danger)', fontSize: '13px', background: 'var(--danger-bg)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.3)' }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {isLoading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent)', fontSize: '13px', padding: '12px 0' }}>
            <div className="pulse-dot" style={{ backgroundColor: 'var(--accent)', boxShadow: '0 0 8px var(--accent)' }} />
            Querying trust-aware RAG pipeline and citing verified sources...
          </div>
        )}

        {response && !isLoading && (
          <div className="chat-response">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                RAG Response
              </span>
              <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
                Retrieved: <strong style={{ color: 'var(--safe)' }}>{response.retrieved_count ?? trustedSources.length}</strong> trusted document(s)
              </span>
            </div>

            <div className="chat-answer-text">
              {response.answer}
            </div>

            {trustedSources.length > 0 && (
              <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-color)', paddingTop: '14px' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
                  Cited Trusted Sources ({trustedSources.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {trustedSources.map((src, idx) => (
                    <div key={src.document_id || idx} className="source-card">
                      <div className="source-header">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <ShieldCheck size={14} color="var(--safe)" />
                          <span style={{ letterSpacing: '0.5px' }}>TRUSTED SOURCE</span>
                        </div>
                        <span className="badge badge-safe">
                          {src.decision || 'SAFE'}
                        </span>
                      </div>
                      <div style={{ fontWeight: 600, color: '#fff', fontSize: '13px', marginTop: '2px' }}>
                        {src.title || 'Untitled Document'}
                      </div>
                      <div style={{ display: 'flex', gap: '16px', fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
                        <span>Source: <span style={{ color: 'var(--text-muted)' }}>{src.source || 'Unknown'}</span></span>
                        <span>Risk Score: <span style={{ color: 'var(--safe)', fontFamily: 'monospace' }}>{(src.risk_score ?? 0).toFixed(3)}</span></span>
                      </div>
                      {src.content && (
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px', background: 'rgba(0,0,0,0.2)', padding: '8px 10px', borderRadius: '4px', fontStyle: 'italic' }}>
                          "{src.content.length > 200 ? src.content.slice(0, 200) + '...' : src.content}"
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </form>
    </div>
  );
}
