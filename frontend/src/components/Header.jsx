import React from 'react';
import { ShieldCheck, RefreshCw, AlertCircle } from 'lucide-react';

export default function Header({ isConnected, isRefreshing, onManualRefresh, lastUpdated }) {
  return (
    <header className="header">
      <div className="header-title-group">
        <h1>
          <ShieldCheck size={28} color="#38bdf8" />
          ADAPTIVESHIELD RAG
        </h1>
        <div className="header-subtitle">Real-Time RAG Security Monitor</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {lastUpdated && (
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
            Updated: {lastUpdated.toLocaleTimeString()}
          </span>
        )}
        <button
          onClick={onManualRefresh}
          disabled={isRefreshing}
          className="btn"
          style={{
            background: 'var(--bg-input)',
            color: 'var(--text-main)',
            border: '1px solid var(--border-color)',
            padding: '6px 12px',
            fontSize: '12px',
          }}
          title="Refresh dashboard data"
        >
          <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} />
          Refresh
        </button>
        <div className="live-badge" style={{ borderColor: isConnected ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)' }}>
          {isConnected ? (
            <>
              <div className="pulse-dot" />
              <span>LIVE SYSTEM</span>
            </>
          ) : (
            <>
              <AlertCircle size={14} color="#ef4444" />
              <span style={{ color: '#ef4444' }}>OFFLINE</span>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
