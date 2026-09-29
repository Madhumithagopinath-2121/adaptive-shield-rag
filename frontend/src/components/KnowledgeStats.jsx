import React from 'react';
import { Database, ShieldCheck, AlertOctagon, Layers } from 'lucide-react';

export default function KnowledgeStats({ statsData }) {
  const trustedCount = statsData?.trusted_count ?? 0;
  const quarantineCount = statsData?.quarantine_count ?? 0;
  const totalIndexed = statsData?.total_indexed ?? 0;
  const modelName = statsData?.embedding_model || 'sentence-transformers/all-MiniLM-L6-v2';

  return (
    <div className="card">
      <div className="card-title">
        <Database size={16} color="var(--accent)" />
        Physical Vector Knowledge Segregation
      </div>
      <div className="store-split">
        <div className="store-box store-trusted">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--safe)', fontWeight: 600, fontSize: '13px' }}>
            <ShieldCheck size={18} />
            TRUSTED KNOWLEDGE BASE
          </div>
          <div className="store-count" style={{ color: 'var(--safe)' }}>
            {trustedCount}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Active verified knowledge eligible for RAG retrieval.
          </div>
        </div>

        <div className="store-box store-quarantine">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--warning)', fontWeight: 600, fontSize: '13px' }}>
            <AlertOctagon size={18} />
            QUARANTINED REPOSITORY
          </div>
          <div className="store-count" style={{ color: 'var(--warning)' }}>
            {quarantineCount}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Isolated suspicious payloads. Strictly excluded from RAG retrieval.
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', paddingTop: '12px', borderTop: '1px solid var(--border-color)', fontSize: '12px', color: 'var(--text-dim)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Layers size={14} />
          Total Indexed: <span style={{ color: '#fff', fontWeight: 600 }}>{totalIndexed}</span>
        </div>
        <div style={{ fontFamily: 'monospace' }}>
          Model: {modelName.split('/').pop()}
        </div>
      </div>
    </div>
  );
}
