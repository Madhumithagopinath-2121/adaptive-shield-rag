import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import ThreatMetrics from './components/ThreatMetrics';
import KnowledgeStats from './components/KnowledgeStats';
import SimulationControls from './components/SimulationControls';
import RAGChat from './components/RAGChat';
import { getThreatState, getKnowledgeStats, startSimulation } from './services/api';

export default function App() {
  const [threatData, setThreatData] = useState(null);
  const [statsData, setStatsData] = useState(null);
  const [isConnected, setIsConnected] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [latestSimulation, setLatestSimulation] = useState(null);

  const fetchData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [threat, stats] = await Promise.all([
        getThreatState(),
        getKnowledgeStats(),
      ]);
      setThreatData(threat);
      setStatsData(stats);
      setIsConnected(true);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
      setIsConnected(false);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleStartSimulation = async (params) => {
    setIsSimulating(true);
    try {
      const result = await startSimulation(params);
      setLatestSimulation(result);
      await fetchData();
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="dashboard-container">
      <Header
        isConnected={isConnected}
        isRefreshing={isRefreshing}
        onManualRefresh={fetchData}
        lastUpdated={lastUpdated}
      />
      <ThreatMetrics threatData={threatData} />
      <div className="dashboard-columns">
        <KnowledgeStats statsData={statsData} />
        <SimulationControls
          isSimulating={isSimulating}
          onStartSimulation={handleStartSimulation}
          latestSimulation={latestSimulation}
        />
      </div>
      <RAGChat />
    </div>
  );
}
