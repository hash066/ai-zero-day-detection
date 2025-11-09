export interface ThreatAlert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  source: string;
  destination?: string;
  score: number;
  description: string;
  status: 'active' | 'investigating' | 'resolved' | 'false_positive';
  affectedDevices: string[];
}

export interface SystemMetrics {
  cpuUsage: number;
  memoryUsage: number;
  networkTraffic: number;
  activeConnections: number;
  anomalyScore: number;
}

export interface Device {
  id: string;
  name: string;
  ip: string;
  status: 'online' | 'offline' | 'compromised' | 'isolated';
  riskScore: number;
  lastSeen: string;
  os: string;
}

export interface NetworkFlow {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  bytes: number;
  packets: number;
  timestamp: string;
  anomalyScore: number;
}

export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  lastTrained: string;
  totalPredictions: number;
}

export interface TimeSeriesData {
  timestamp: string;
  value: number;
  label?: string;
}

export interface DashboardStats {
  totalAlerts: number;
  activeThreats: number;
  devicesMonitored: number;
  avgRiskScore: number;
  trendsData: {
    alerts: TimeSeriesData[];
    anomalyScore: TimeSeriesData[];
    networkTraffic: TimeSeriesData[];
  };
}
