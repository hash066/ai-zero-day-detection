import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, Monitor } from 'lucide-react';
import { DeviceCard } from '../components/DeviceCard';
import { mockDevices } from '../services/mockData';
import type { Device } from '../types';

export function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | Device['status']>('all');

  useEffect(() => {
    setDevices(mockDevices());
  }, []);

  const filteredDevices = devices.filter((device) => {
    const matchesSearch =
      device.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      device.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      device.os.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus = statusFilter === 'all' || device.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const stats = {
    total: devices.length,
    online: devices.filter((d) => d.status === 'online').length,
    compromised: devices.filter((d) => d.status === 'compromised').length,
    isolated: devices.filter((d) => d.status === 'isolated').length,
    avgRisk: devices.reduce((sum, d) => sum + d.riskScore, 0) / devices.length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-dark-50 mb-2">Network Devices</h1>
        <p className="text-dark-400">Monitor and manage connected devices</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatBox label="Total Devices" value={stats.total} />
        <StatBox label="Online" value={stats.online} color="text-green-500" />
        <StatBox label="Compromised" value={stats.compromised} color="text-red-500" />
        <StatBox label="Isolated" value={stats.isolated} color="text-orange-500" />
        <StatBox label="Avg Risk" value={stats.avgRisk.toFixed(1)} color="text-yellow-500" />
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
            <input
              type="text"
              placeholder="Search devices..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input w-full pl-10"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            className="input"
          >
            <option value="all">All Status</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="compromised">Compromised</option>
            <option value="isolated">Isolated</option>
          </select>
        </div>
      </div>

      {/* Devices Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredDevices.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="col-span-full card text-center py-12"
          >
            <Monitor className="w-12 h-12 text-dark-600 mx-auto mb-4" />
            <p className="text-dark-400">No devices found matching your criteria</p>
          </motion.div>
        ) : (
          filteredDevices.map((device, index) => (
            <motion.div
              key={device.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.05 }}
            >
              <DeviceCard device={device} />
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
