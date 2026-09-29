import React from 'react';
import { Activity, ShieldAlert, BarChart3, AlertTriangle, ShieldX, Database } from 'lucide-react';

export default function ThreatMetrics({ threatData }) {
  const state = threatData?.state || 'NORMAL';
  const velocity = threatData?.attack_velocity !== undefined ? (threatData.attack_velocity * 100).toFixed(1) + '%' : '0.0%';
  const blockRate = threatData?.block_rate !== undefined ? (threatData.block_rate * 100).toFixed(1) + '%' : '0.0%';
  const quarRate = threatData?.quarantine_rate !== undefined ? (threatData.quarantine_rate * 100).toFixed(1) + '%' : '0.0%';
  const avgRisk = threatData?.average_risk_score !== undefined ? threatData.average_risk_score.toFixed(3) : '0.000';
  const totalAssessed = threatData?.total_assessed ?? 0;

  const getStateClass = (s) => {
    switch (s?.toUpperCase()) {
      case 'CRITICAL':
        return 'state-critical';
      case 'HIGH':
        return 'state-high';
      case 'ELEVATED':
        return 'state-elevated';
      default:
        return 'state-normal';
    }
  };

  return (
    <div className="metrics-grid">
      <div className="metric-card" style={{ gridColumn: 'span 2' }}>
        <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <ShieldAlert size={14} color="var(--accent)" />
          Stream Threat State
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '4px' }}>
          <span className={`state-pill ${getStateClass(state)}`}>
            {state}
          </span>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {threatData?.state_reason || 'Observing incoming document stream...'}
          </span>
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Activity size={14} color="#f97316" />
          Attack Velocity
        </div>
        <div className="metric-value" style={{ color: threatData?.attack_velocity >= 0.25 ? '#ef4444' : '#fff' }}>
          {velocity}
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Suspicious rate / window</div>
      </div>

      <div className="metric-card">
        <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <ShieldX size={14} color="var(--danger)" />
          Block Rate
        </div>
        <div className="metric-value" style={{ color: threatData?.block_rate >= 0.15 ? '#ef4444' : '#fff' }}>
          {blockRate}
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
          {threatData?.block_count ?? 0} blocked documents
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <AlertTriangle size={14} color="var(--warning)" />
          Quarantine Rate
        </div>
        <div className="metric-value" style={{ color: threatData?.quarantine_rate >= 0.3 ? '#f59e0b' : '#fff' }}>
          {quarRate}
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
          {threatData?.quarantine_count ?? 0} quarantined documents
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <BarChart3 size={14} color="#a855f7" />
          Average Risk Score
        </div>
        <div className="metric-value">
          {avgRisk}
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Normalized range [0.0 - 1.0]</div>
      </div>

      <div className="metric-card">
        <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Database size={14} color="#38bdf8" />
          Total Assessed
        </div>
        <div className="metric-value">
          {totalAssessed}
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Within rolling 300s window</div>
      </div>
    </div>
  );
}
