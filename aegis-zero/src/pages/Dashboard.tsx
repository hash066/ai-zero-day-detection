import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Activity, TrendingUp } from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { AlertCard } from '../components/AlertCard';
import { Chart } from '../components/Chart';
import { mockDashboardStats, mockAlerts, mockSystemMetrics } from '../services/mockData';
import type { DashboardStats, ThreatAlert, SystemMetrics } from '../types';

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);

  useEffect(() => {
    // Simulate API calls - replace with actual API service
    setStats(mockDashboardStats());
    setAlerts(mockAlerts().slice(0, 5));
    setMetrics(mockSystemMetrics());

    // Refresh metrics every 5 seconds
    const interval = setInterval(() => {
      setMetrics(mockSystemMetrics());
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  if (!stats || !metrics) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-dark-50 mb-2">Security Dashboard</h1>
        <p className="text-dark-400">Real-time threat monitoring and analysis</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Active Threats"
          value={stats.activeThreats}
          icon={<AlertTriangle className="w-6 h-6" />}
          trend={{ value: 12, isPositive: false }}
        />
        <StatCard
          title="Total Alerts"
          value={stats.totalAlerts}
          icon={<Shield className="w-6 h-6" />}
          trend={{ value: 8, isPositive: true }}
        />
        <StatCard
          title="Devices Monitored"
          value={stats.devicesMonitored}
          icon={<Activity className="w-6 h-6" />}
        />
        <StatCard
          title="Avg Risk Score"
          value={stats.avgRiskScore.toFixed(1)}
          icon={<TrendingUp className="w-6 h-6" />}
          trend={{ value: 3, isPositive: false }}
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="card"
        >
          <h2 className="text-lg font-semibold text-dark-50 mb-4">Anomaly Score Trend</h2>
          <Chart data={stats.trendsData.anomalyScore} color="#f59e0b" height={250} />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="card"
        >
          <h2 className="text-lg font-semibold text-dark-50 mb-4">Network Traffic</h2>
          <Chart data={stats.trendsData.networkTraffic} color="#0ea5e9" height={250} />
        </motion.div>
      </div>

      {/* System Metrics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="card"
      >
        <h2 className="text-lg font-semibold text-dark-50 mb-4">System Metrics</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <MetricItem label="CPU Usage" value={`${metrics.cpuUsage.toFixed(1)}%`} />
          <MetricItem label="Memory Usage" value={`${metrics.memoryUsage.toFixed(1)}%`} />
          <MetricItem label="Network Traffic" value={`${metrics.networkTraffic.toFixed(0)} MB/s`} />
          <MetricItem label="Connections" value={metrics.activeConnections.toLocaleString()} />
          <MetricItem label="Anomaly Score" value={metrics.anomalyScore.toFixed(2)} />
        </div>
      </motion.div>

      {/* Recent Alerts */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-dark-50">Recent Threats</h2>
          <button className="text-sm text-primary-400 hover:text-primary-300 transition-colors">
            View All →
          </button>
        </div>
        <div className="space-y-4">
          {alerts.map((alert, index) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <AlertCard alert={alert} />
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}

function MetricItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-dark-800 rounded-lg p-4">
      <div className="text-xs text-dark-400 mb-1">{label}</div>
      <div className="text-lg font-semibold text-dark-50">{value}</div>
    </div>
  );
}
