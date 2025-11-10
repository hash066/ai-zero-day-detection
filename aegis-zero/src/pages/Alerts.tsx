import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, Filter, AlertTriangle } from 'lucide-react';
import { AlertCard } from '../components/AlertCard';
import { mockAlerts } from '../services/mockData';
import type { ThreatAlert } from '../types';

const severityFilters = ['all', 'critical', 'high', 'medium', 'low'] as const;
const statusFilters = ['all', 'active', 'investigating', 'resolved', 'false_positive'] as const;

export function Alerts() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<typeof severityFilters[number]>('all');
  const [statusFilter, setStatusFilter] = useState<typeof statusFilters[number]>('all');

  useEffect(() => {
    // Simulate API call
    const allAlerts = mockAlerts();
    setAlerts(allAlerts);
  }, []);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.source.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || alert.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const stats = {
    total: alerts.length,
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    active: alerts.filter((a) => a.status === 'active').length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-dark-50 mb-2">Threat Alerts</h1>
        <p className="text-dark-400">Monitor and manage security threats</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatBox label="Total Alerts" value={stats.total} />
        <StatBox label="Critical" value={stats.critical} color="text-red-500" />
        <StatBox label="High Priority" value={stats.high} color="text-orange-500" />
        <StatBox label="Active" value={stats.active} color="text-yellow-500" />
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
            <input
              type="text"
              placeholder="Search alerts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input w-full pl-10"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-dark-500" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as typeof severityFilter)}
              className="input"
            >
              {severityFilters.map((filter) => (
                <option key={filter} value={filter}>
                  {filter.charAt(0).toUpperCase() + filter.slice(1)}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            className="input"
          >
            {statusFilters.map((filter) => (
              <option key={filter} value={filter}>
                {filter === 'all' ? 'All Status' : filter.replace('_', ' ').charAt(0).toUpperCase() + filter.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Alerts List */}
      <div className="space-y-4">
        {filteredAlerts.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="card text-center py-12"
          >
            <AlertTriangle className="w-12 h-12 text-dark-600 mx-auto mb-4" />
            <p className="text-dark-400">No alerts found matching your criteria</p>
          </motion.div>
        ) : (
          filteredAlerts.map((alert, index) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <AlertCard alert={alert} />
            </motion.div>
          ))
        )}
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
  value: number;
  color?: string;
}) {
  return (
    <div className="card">
      <div className="text-sm text-dark-400 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}
