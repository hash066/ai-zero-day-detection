import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, ArrowUpDown, Network } from 'lucide-react';
import { Chart } from '../components/Chart';
import { mockNetworkFlows, mockDashboardStats } from '../services/mockData';
import type { NetworkFlow } from '../types';

export function NetworkMonitor() {
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [sortBy, setSortBy] = useState<'timestamp' | 'bytes' | 'anomalyScore'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    setFlows(mockNetworkFlows());
  }, []);

  const sortedFlows = [...flows].sort((a, b) => {
    const multiplier = sortOrder === 'asc' ? 1 : -1;
    
    if (sortBy === 'timestamp') {
      return multiplier * (new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }
    
    return multiplier * (b[sortBy] - a[sortBy]);
  });

  const stats = {
    totalFlows: flows.length,
    totalBytes: flows.reduce((sum, f) => sum + f.bytes, 0),
    totalPackets: flows.reduce((sum, f) => sum + f.packets, 0),
    avgAnomalyScore: flows.reduce((sum, f) => sum + f.anomalyScore, 0) / flows.length,
    highRiskFlows: flows.filter((f) => f.anomalyScore > 7).length,
  };

  const trendsData = mockDashboardStats().trendsData.networkTraffic;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-dark-50 mb-2">Network Monitor</h1>
        <p className="text-dark-400">Real-time network traffic analysis</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatBox label="Total Flows" value={stats.totalFlows.toLocaleString()} />
        <StatBox label="Total Bytes" value={`${(stats.totalBytes / 1024 / 1024).toFixed(2)} MB`} />
        <StatBox label="Total Packets" value={stats.totalPackets.toLocaleString()} />
        <StatBox
          label="Avg Anomaly Score"
          value={stats.avgAnomalyScore.toFixed(2)}
          color="text-yellow-500"
        />
        <StatBox label="High Risk Flows" value={stats.highRiskFlows} color="text-red-500" />
      </div>

      {/* Network Traffic Chart */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-dark-50">Traffic Trend</h2>
          <div className="flex items-center gap-2 text-sm text-dark-400">
            <Activity className="w-4 h-4" />
            <span>Last 24 hours</span>
          </div>
        </div>
        <Chart data={trendsData} color="#0ea5e9" height={300} />
      </motion.div>

      {/* Network Flows Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-dark-50">Recent Network Flows</h2>
          <div className="flex items-center gap-2">
            <ArrowUpDown className="w-4 h-4 text-dark-500" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
              className="input py-1 text-sm"
            >
              <option value="timestamp">Time</option>
              <option value="bytes">Bytes</option>
              <option value="anomalyScore">Risk Score</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-800">
                <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Source</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Destination</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Protocol</th>
                <th className="text-right py-3 px-4 text-sm font-medium text-dark-400">Bytes</th>
                <th className="text-right py-3 px-4 text-sm font-medium text-dark-400">Packets</th>
                <th className="text-right py-3 px-4 text-sm font-medium text-dark-400">Risk Score</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Time</th>
              </tr>
            </thead>
            <tbody>
              {sortedFlows.slice(0, 20).map((flow) => (
                <motion.tr
                  key={flow.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors"
                >
                  <td className="py-3 px-4 text-sm text-dark-100">
                    {flow.srcIp}:{flow.srcPort}
                  </td>
                  <td className="py-3 px-4 text-sm text-dark-100">
                    {flow.dstIp}:{flow.dstPort}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-1 rounded text-xs font-medium bg-primary-600/10 text-primary-400">
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-dark-100 text-right">
                    {flow.bytes.toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-sm text-dark-100 text-right">
                    {flow.packets.toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <span
                      className={`font-semibold ${
                        flow.anomalyScore > 7
                          ? 'text-red-500'
                          : flow.anomalyScore > 5
                          ? 'text-orange-500'
                          : 'text-green-500'
                      }`}
                    >
                      {flow.anomalyScore.toFixed(2)}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-dark-400">
                    {new Date(flow.timestamp).toLocaleTimeString()}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatBox({
  label,
  value,
  color = 'text-dark-50',
}: {
  label: string;
  value: number | string;
  color?: string;
}) {
  return (
    <div className="card">
      <div className="text-sm text-dark-400 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}
