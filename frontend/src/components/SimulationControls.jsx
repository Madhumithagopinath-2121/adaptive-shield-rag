import React from 'react';
import { Play, ShieldAlert, Sparkles, CheckCircle2, AlertTriangle, ShieldX } from 'lucide-react';

export default function SimulationControls({ isSimulating, onStartSimulation, latestSimulation }) {
  return (
    <div className="card">
      <div className="card-title">
        <Play size={16} color="var(--accent)" />
        Live Knowledge Stream & Attack Simulator
      </div>
      <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '14px' }}>
        Inject controlled synthetic document batches into the live ingestion and defense pipeline to demonstrate adaptive threat response.
      </div>

      <div className="sim-controls">
        <button
          onClick={() => onStartSimulation({ mode: 'normal', document_count: 10, attack_ratio: 0.10, delay_ms: 0 })}
          disabled={isSimulating}
          className="btn btn-normal"
        >
          <CheckCircle2 size={16} />
          NORMAL STREAM (10 Docs)
        </button>

        <button
          onClick={() => onStartSimulation({ mode: 'attack', document_count: 10, attack_ratio: 0.80, delay_ms: 0 })}
          disabled={isSimulating}
          className="btn btn-attack"
        >
          <ShieldAlert size={16} />
          ATTACK SIMULATION (80% Adversarial)
        </button>

        <button
          onClick={() => onStartSimulation({ mode: 'mixed', document_count: 10, attack_ratio: 0.50, delay_ms: 0 })}
          disabled={isSimulating}
          className="btn btn-mixed"
        >
          <Sparkles size={16} />
          MIXED STREAM (50/50 Balance)
        </button>
      </div>

      {isSimulating && (
        <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent)', fontSize: '13px' }}>
          <div className="pulse-dot" style={{ backgroundColor: 'var(--accent)', boxShadow: '0 0 8px var(--accent)' }} />
          Simulating live document ingestion and security triage in progress...
        </div>
      )}

      {latestSimulation && (
        <div style={{ marginTop: '18px', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
              Latest Simulation Summary ({latestSimulation.mode})
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
              ID: {latestSimulation.simulation_id.slice(0, 8)}... ({latestSimulation.duration_ms}ms)
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
            <div style={{ background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>TOTAL GENERATED</div>
              <div style={{ fontSize: '18px', fontWeight: 700 }}>{latestSimulation.total_generated}</div>
            </div>
            <div style={{ background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--safe)' }}>SAFE (TRUSTED)</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--safe)' }}>{latestSimulation.safe_count}</div>
            </div>
            <div style={{ background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--warning)' }}>QUARANTINE</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--warning)' }}>{latestSimulation.quarantine_count}</div>
            </div>
            <div style={{ background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--danger)' }}>BLOCK (REJECTED)</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--danger)' }}>{latestSimulation.block_count}</div>
            </div>
            <div style={{ background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>ATTACK VELOCITY</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: latestSimulation.attack_velocity >= 0.25 ? '#ef4444' : '#fff' }}>
                {(latestSimulation.attack_velocity * 100).toFixed(1)}%
              </div>
            </div>
            <div style={{ background: 'var(--bg-input)', padding: '8px 12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>RESULTING STATE</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: latestSimulation.current_threat_state === 'CRITICAL' ? '#ef4444' : latestSimulation.current_threat_state === 'HIGH' ? '#f97316' : '#10b981' }}>
                {latestSimulation.current_threat_state}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
