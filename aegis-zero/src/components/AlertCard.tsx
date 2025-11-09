import { motion } from 'framer-motion';
import { AlertTriangle, Clock, MapPin } from 'lucide-react';
import { cn } from '../lib/utils';
import type { ThreatAlert } from '../types';
import { formatDistanceToNow } from 'date-fns';

interface AlertCardProps {
  alert: ThreatAlert;
  onClick?: () => void;
}

const severityConfig = {
  critical: {
    bg: 'bg-red-500/10',
    text: 'text-red-500',
    border: 'border-red-500/20',
  },
  high: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-500',
    border: 'border-orange-500/20',
  },
  medium: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-500',
    border: 'border-yellow-500/20',
  },
  low: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-500',
    border: 'border-blue-500/20',
  },
};

const statusConfig = {
  active: { label: 'Active', color: 'bg-red-500' },
  investigating: { label: 'Investigating', color: 'bg-yellow-500' },
  resolved: { label: 'Resolved', color: 'bg-green-500' },
  false_positive: { label: 'False Positive', color: 'bg-gray-500' },
};

export function AlertCard({ alert, onClick }: AlertCardProps) {
  const severity = severityConfig[alert.severity];
  const status = statusConfig[alert.status];

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      whileHover={{ scale: 1.01 }}
      onClick={onClick}
      className={cn(
        'card cursor-pointer transition-all duration-200',
        severity.border,
        'hover:shadow-xl'
      )}
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-start gap-3 flex-1">
          <div className={cn('p-2 rounded-lg', severity.bg)}>
            <AlertTriangle className={cn('w-5 h-5', severity.text)} />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold text-dark-50">{alert.type}</h3>
              <span
                className={cn(
                  'px-2 py-0.5 rounded-full text-xs font-medium uppercase',
                  severity.bg,
                  severity.text
                )}
              >
                {alert.severity}
              </span>
            </div>
            <p className="text-sm text-dark-400 line-clamp-2">{alert.description}</p>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-1.5">
            <div className={cn('w-2 h-2 rounded-full', status.color)} />
            <span className="text-xs text-dark-400">{status.label}</span>
          </div>
          <div className="text-right">
            <div className="text-lg font-bold text-dark-50">{alert.score.toFixed(1)}</div>
            <div className="text-xs text-dark-500">Risk Score</div>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-4 text-xs text-dark-500 pt-3 border-t border-dark-800">
        <div className="flex items-center gap-1">
          <MapPin className="w-3.5 h-3.5" />
          <span>{alert.source}</span>
          {alert.destination && (
            <>
              <span>→</span>
              <span>{alert.destination}</span>
            </>
          )}
        </div>
        <div className="flex items-center gap-1">
          <Clock className="w-3.5 h-3.5" />
          <span>{formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}</span>
        </div>
      </div>
    </motion.div>
  );
}
