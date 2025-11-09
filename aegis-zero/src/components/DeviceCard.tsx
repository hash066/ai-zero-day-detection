import { motion } from 'framer-motion';
import { Monitor, Wifi, WifiOff, Shield, ShieldAlert } from 'lucide-react';
import { cn } from '../lib/utils';
import type { Device } from '../types';
import { formatDistanceToNow } from 'date-fns';

interface DeviceCardProps {
  device: Device;
  onClick?: () => void;
}

const statusConfig = {
  online: {
    icon: Wifi,
    color: 'text-green-500',
    bg: 'bg-green-500/10',
    label: 'Online',
  },
  offline: {
    icon: WifiOff,
    color: 'text-gray-500',
    bg: 'bg-gray-500/10',
    label: 'Offline',
  },
  compromised: {
    icon: ShieldAlert,
    color: 'text-red-500',
    bg: 'bg-red-500/10',
    label: 'Compromised',
  },
  isolated: {
    icon: Shield,
    color: 'text-orange-500',
    bg: 'bg-orange-500/10',
    label: 'Isolated',
  },
};

export function DeviceCard({ device, onClick }: DeviceCardProps) {
  const config = statusConfig[device.status];
  const StatusIcon = config.icon;
  const riskColor =
    device.riskScore >= 7
      ? 'text-red-500'
      : device.riskScore >= 5
      ? 'text-orange-500'
      : 'text-green-500';

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      whileHover={{ scale: 1.02 }}
      onClick={onClick}
      className="card cursor-pointer hover:shadow-xl transition-all duration-200"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-start gap-3 flex-1">
          <div className="p-2 bg-primary-600/10 rounded-lg">
            <Monitor className="w-5 h-5 text-primary-400" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-dark-50 mb-0.5">{device.name}</h3>
            <p className="text-sm text-dark-400">{device.ip}</p>
            <p className="text-xs text-dark-500 mt-1">{device.os}</p>
          </div>
        </div>
        <div className={cn('p-2 rounded-lg', config.bg)}>
          <StatusIcon className={cn('w-4 h-4', config.color)} />
        </div>
      </div>

      <div className="flex items-center justify-between pt-3 border-t border-dark-800">
        <div className="flex items-center gap-2">
          <span className="text-xs text-dark-500">Status:</span>
          <span className={cn('text-xs font-medium', config.color)}>
            {config.label}
          </span>
        </div>
        <div className="text-right">
          <div className={cn('text-lg font-bold', riskColor)}>
            {device.riskScore.toFixed(1)}
          </div>
          <div className="text-xs text-dark-500">Risk Score</div>
        </div>
      </div>

      <div className="text-xs text-dark-500 mt-2 flex items-center gap-1">
        <span>Last seen:</span>
        <span>{formatDistanceToNow(new Date(device.lastSeen), { addSuffix: true })}</span>
      </div>
    </motion.div>
  );
}
