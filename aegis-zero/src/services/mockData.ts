import type { 
  ThreatAlert, 
  SystemMetrics, 
  Device, 
  NetworkFlow, 
  ModelMetrics, 
  DashboardStats,
  TimeSeriesData
} from '../types';

// Mock data generators for development
export const mockDashboardStats = (): DashboardStats => ({
  totalAlerts: 127,
  activeThreats: 8,
  devicesMonitored: 45,
  avgRiskScore: 6.3,
  trendsData: {
    alerts: generateTimeSeriesData(24, 0, 15),
    anomalyScore: generateTimeSeriesData(24, 0, 10),
    networkTraffic: generateTimeSeriesData(24, 100, 500),
  },
});

export const mockAlerts = (): ThreatAlert[] => [
  {
    id: '1',
    timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
    severity: 'critical',
    type: 'Zero-Day Exploit Detected',
    source: '192.168.1.145',
    destination: '10.0.0.5',
    score: 9.7,
    description: 'Unusual system call sequence detected indicating potential privilege escalation',
    status: 'active',
    affectedDevices: ['WS-USER-145', 'SRV-DB-01'],
  },
  {
    id: '2',
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    severity: 'high',
    type: 'Anomalous Network Pattern',
    source: '192.168.1.67',
    score: 8.2,
    description: 'Unusual port scanning activity from internal host',
    status: 'investigating',
    affectedDevices: ['WS-USER-067'],
  },
  {
    id: '3',
    timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
    severity: 'medium',
    type: 'Suspicious File Access',
    source: '192.168.1.89',
    score: 6.5,
    description: 'Unexpected access to sensitive system files',
    status: 'investigating',
    affectedDevices: ['WS-USER-089'],
  },
  {
    id: '4',
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    severity: 'high',
    type: 'Unusual Memory Pattern',
    source: '192.168.1.23',
    score: 7.8,
    description: 'Abnormal memory allocation pattern detected',
    status: 'resolved',
    affectedDevices: ['WS-USER-023'],
  },
  {
    id: '5',
    timestamp: new Date(Date.now() - 60 * 60000).toISOString(),
    severity: 'low',
    type: 'Minor Behavioral Anomaly',
    source: '192.168.1.156',
    score: 4.2,
    description: 'Slight deviation from normal network behavior',
    status: 'false_positive',
    affectedDevices: ['WS-USER-156'],
  },
];

export const mockSystemMetrics = (): SystemMetrics => ({
  cpuUsage: 67 + Math.random() * 10,
  memoryUsage: 73 + Math.random() * 10,
  networkTraffic: 234 + Math.random() * 50,
  activeConnections: 1247 + Math.floor(Math.random() * 100),
  anomalyScore: 6.3 + Math.random() * 2,
});

export const mockDevices = (): Device[] => [
  {
    id: '1',
    name: 'WS-USER-145',
    ip: '192.168.1.145',
    status: 'compromised',
    riskScore: 9.2,
    lastSeen: new Date().toISOString(),
    os: 'Windows 11',
  },
  {
    id: '2',
    name: 'SRV-DB-01',
    ip: '10.0.0.5',
    status: 'isolated',
    riskScore: 8.7,
    lastSeen: new Date(Date.now() - 5 * 60000).toISOString(),
    os: 'Ubuntu 22.04 LTS',
  },
  {
    id: '3',
    name: 'WS-USER-067',
    ip: '192.168.1.67',
    status: 'online',
    riskScore: 7.5,
    lastSeen: new Date().toISOString(),
    os: 'Windows 11',
  },
  {
    id: '4',
    name: 'WS-USER-089',
    ip: '192.168.1.89',
    status: 'online',
    riskScore: 5.8,
    lastSeen: new Date().toISOString(),
    os: 'macOS 14',
  },
  {
    id: '5',
    name: 'SRV-WEB-02',
    ip: '10.0.0.12',
    status: 'online',
    riskScore: 3.2,
    lastSeen: new Date().toISOString(),
    os: 'CentOS 8',
  },
];

export const mockNetworkFlows = (): NetworkFlow[] => {
  const flows: NetworkFlow[] = [];
  const protocols = ['TCP', 'UDP', 'ICMP'];
  
  for (let i = 0; i < 50; i++) {
    flows.push({
      id: `flow-${i}`,
      srcIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
      dstIp: `10.0.0.${Math.floor(Math.random() * 255)}`,
      srcPort: Math.floor(Math.random() * 65535),
      dstPort: Math.floor(Math.random() * 65535),
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      bytes: Math.floor(Math.random() * 10000),
      packets: Math.floor(Math.random() * 1000),
      timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      anomalyScore: Math.random() * 10,
    });
  }
  
  return flows.sort((a, b) => 
    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
};

export const mockModelMetrics = (): ModelMetrics => ({
  accuracy: 0.947,
  precision: 0.923,
  recall: 0.956,
  f1Score: 0.939,
  lastTrained: new Date(Date.now() - 24 * 3600000).toISOString(),
  totalPredictions: 15234,
});

function generateTimeSeriesData(
  points: number,
  min: number,
  max: number
): TimeSeriesData[] {
  const data: TimeSeriesData[] = [];
  const now = Date.now();
  
  for (let i = points - 1; i >= 0; i--) {
    data.push({
      timestamp: new Date(now - i * 3600000).toISOString(),
      value: min + Math.random() * (max - min),
    });
  }
  
  return data;
}
