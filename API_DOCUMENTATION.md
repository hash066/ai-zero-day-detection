# AI Zero-Day Detection Dashboard API Documentation

## Overview

This document specifies all API endpoints required for the frontend dashboard integration with the AI Zero-Day Detection backend. The API serves real-time security monitoring data, threat intelligence, and system metrics.

**Base URL:** `http://localhost:8000/api` (Frontend expects `/api` prefix)
**Backend Current URL:** `http://localhost:8000` (Routes prefixed with `/api`)

---

## Authentication

Currently no authentication implemented. All endpoints are public.

---

## Response Format

All responses follow this structure:

```json
{
  "data": <response_data>,
  "error": null | "error_message",
  "timestamp": "2025-11-11T20:16:28Z"
}
```

For collections:
```json
{
  "data": [...],
  "total": 100,
  "page": 1,
  "limit": 50
}
```

---

## Endpoints

### 1. Health & Root

#### GET /
**Description:** API root endpoint
**Status:** ✅ Implemented
**Response:**
```json
{
  "message": "Welcome to the Zero-Day Threat Detector API"
}
```

#### GET /health
**Description:** Health check endpoint
**Status:** ✅ Implemented
**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-11-11T20:16:28Z",
  "version": "1.0.0"
}
```

---

### 2. Dashboard Statistics

#### GET /dashboard/stats
**Description:** Get dashboard overview statistics
**Status:** ✅ Implemented (mock data)
**Response:**
```json
{
  "totalAlerts": 3,
  "activeThreats": 2,
  "devicesMonitored": 5,
  "avgRiskScore": 7.8,
  "trendsData": {
    "alerts": [
      {
        "timestamp": "2025-11-12T01:00:00Z",
        "value": 2
      }
    ],
    "anomalyScore": [
      {
        "timestamp": "2025-11-12T01:00:00Z",
        "value": 7.8
      }
    ],
    "networkTraffic": [
      {
        "timestamp": "2025-11-12T01:00:00Z",
        "value": 150.5
      }
    ]
  }
}
```

---

### 3. Threat Alerts

#### GET /alerts
**Description:** Get list of security alerts
**Status:** ✅ Implemented (mock fallback when DB unavailable)
**Query Parameters:**
- `limit` (number, default: 50) - Number of alerts to return

**Response:**
```json
[
  {
    "_id": "mock_1",
    "entity_id": "192.168.1.15",
    "threat_score": 0.85,
    "timestamp": "2025-11-12T01:17:34Z",
    "metadata": {
      "reason": "Anomalous process sequence detected",
      "is_mock": true
    }
  }
]
```

#### GET /alerts/{alert_id}
**Description:** Get specific alert details
**Status:** ✅ Implemented (mock fallback when DB unavailable)
**Path Parameters:**
- `alert_id` (string) - Alert identifier

**Response:** Single alert object (same structure as above)

#### PATCH /alerts/{alert_id}
**Description:** Update alert status
**Status:** ✅ Implemented (mock fallback when DB unavailable)
**Path Parameters:**
- `alert_id` (string) - Alert identifier

**Request Body:**
```json
{
  "status": "investigating"
}
```

**Valid Status Values:** "active", "investigating", "resolved", "false_positive"

**Response:** Updated alert object with new status and timestamp

---

### 4. System Metrics

#### GET /metrics/system
**Description:** Get real-time system performance metrics
**Status:** ✅ Implemented (mock data)
**Response:**
```json
{
  "cpuUsage": 67.5,
  "memoryUsage": 73.2,
  "networkTraffic": 234.8,
  "activeConnections": 1247,
  "anomalyScore": 6.3,
  "timestamp": "2025-11-12T01:45:00Z"
}
```

---

### 5. Device Management

#### GET /devices
**Description:** Get list of all monitored devices
**Status:** ✅ Implemented (mock data)
**Query Parameters:**
- `status` (string) - Filter by status: "online", "offline", "compromised", "isolated"
- `limit` (number, default: 100)
- `offset` (number, default: 0)

**Response:**
```json
[
  {
    "id": "device-001",
    "name": "WS-USER-145",
    "ip": "192.168.1.145",
    "status": "compromised",
    "riskScore": 9.2,
    "lastSeen": "2025-11-12T01:40:00Z",
    "os": "Windows 11",
    "macAddress": "00:11:22:33:44:55",
    "location": "Office A"
  }
]
```

#### GET /devices/{device_id}
**Description:** Get detailed device information
**Status:** ✅ Implemented (mock data)
**Path Parameters:**
- `device_id` (string) - Device identifier

**Response:** Single device object with additional process and network details

#### POST /devices/{device_id}/isolate
**Description:** Isolate a compromised device from the network
**Status:** ✅ Implemented (mock data)
**Path Parameters:**
- `device_id` (string) - Device identifier

**Response:**
```json
{
  "id": "device-001",
  "name": "WS-USER-145",
  "status": "isolated",
  "isolationTime": "2025-11-12T01:45:00Z",
  "message": "Device successfully isolated from network"
}
```

---

### 6. Network Monitoring

#### GET /network/flows
**Description:** Get network flow data with anomaly detection
**Status:** ✅ Implemented (mock data)
**Query Parameters:**
- `limit` (number, default: 100) - Number of flows to return
- `startTime` (ISO string) - Filter flows after this time
- `endTime` (ISO string) - Filter flows before this time
- `anomalyOnly` (boolean) - Return only flows with high anomaly scores

**Response:**
```json
[
  {
    "id": "flow-0001",
    "srcIp": "192.168.1.100",
    "dstIp": "10.0.0.5",
    "srcPort": 443,
    "dstPort": 80,
    "protocol": "TCP",
    "bytes": 15432,
    "packets": 123,
    "timestamp": "2025-11-12T01:40:00Z",
    "anomalyScore": 8.7,
    "threatLevel": "high",
    "description": "Suspicious outbound connection to known malicious IP"
  }
]
```

#### GET /network/stats
**Description:** Get network monitoring statistics
**Status:** ✅ Implemented (mock data)
**Response:**
```json
{
  "totalFlows": 25000,
  "activeConnections": 1456,
  "bytesPerSecond": 1500000,
  "packetsPerSecond": 1200,
  "anomalousFlows": 45,
  "threatLevels": {
    "low": 150,
    "medium": 25,
    "high": 12,
    "critical": 3
  }
}
```

---

### 7. AI Model Management

#### GET /models/metrics
**Description:** Get AI model performance metrics
**Status:** ✅ Implemented (mock data)
**Response:**
```json
{
  "accuracy": 0.947,
  "precision": 0.923,
  "recall": 0.956,
  "f1Score": 0.939,
  "lastTrained": "2025-11-10T14:30:00Z",
  "totalPredictions": 15234,
  "modelVersion": "v2.1.0",
  "trainingDataSize": 50000,
  "falsePositiveRate": 0.023,
  "falseNegativeRate": 0.015
}
```

#### POST /models/train
**Description:** Trigger model retraining
**Status:** ✅ Implemented (mock data)
**Request Body:**
```json
{
  "modelType": "ensemble",
  "trainingDataPath": "/path/to/training/data",
  "hyperparameters": {
    "learningRate": 0.001,
    "epochs": 100
  }
}
```

**Response:**
```json
{
  "status": "training_started",
  "jobId": "train-1731350000-123",
  "estimatedDuration": "2 hours",
  "message": "Model training initiated successfully"
}
```

#### GET /models/train/{job_id}
**Description:** Check training job status
**Status:** ✅ Implemented (mock data)
**Response:**
```json
{
  "jobId": "train-1731350000-123",
  "status": "running",
  "progress": 65,
  "currentEpoch": 65,
  "totalEpochs": 100,
  "loss": 0.0234,
  "accuracy": 0.945,
  "estimatedTimeRemaining": "35 minutes"
}
```

#### GET /models/train
**Description:** Get list of training jobs
**Status:** ✅ Implemented (mock data)
**Query Parameters:**
- `status` (string) - Filter by status
- `limit` (number, default: 10)

**Response:** Array of training job objects

#### GET /models/versions
**Description:** Get available model versions
**Status:** ✅ Implemented (mock data)
**Response:** Array of model version objects with metadata

#### POST /models/deploy/{version}
**Description:** Deploy a specific model version
**Status:** ✅ Implemented (mock data)
**Path Parameters:**
- `version` (string) - Model version to deploy

**Response:** Deployment confirmation object

---

## Data Types

### ThreatAlert
```typescript
interface ThreatAlert {
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
```

### SystemMetrics
```typescript
interface SystemMetrics {
  cpuUsage: number;
  memoryUsage: number;
  networkTraffic: number;
  activeConnections: number;
  anomalyScore: number;
}
```

### Device
```typescript
interface Device {
  id: string;
  name: string;
  ip: string;
  status: 'online' | 'offline' | 'compromised' | 'isolated';
  riskScore: number;
  lastSeen: string;
  os: string;
}
```

### NetworkFlow
```typescript
interface NetworkFlow {
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
```

### ModelMetrics
```typescript
interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  lastTrained: string;
  totalPredictions: number;
}
```

### DashboardStats
```typescript
interface DashboardStats {
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
```

### TimeSeriesData
```typescript
interface TimeSeriesData {
  timestamp: string;
  value: number;
  label?: string;
}
```

---

## Error Responses

All endpoints return errors in this format:

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "timestamp": "2025-11-11T20:16:28Z"
}
```

Common HTTP status codes:
- `200` - Success
- `400` - Bad Request
- `404` - Not Found
- `500` - Internal Server Error

---

## Implementation Status

| Endpoint | Method | Status | Priority |
|----------|--------|--------|----------|
| `/` | GET | ✅ Implemented | Low |
| `/health` | GET | ✅ Implemented | Low |
| `/test` | GET | ✅ Implemented (mock data) | Low |
| `/alerts` | GET | ✅ Implemented (mock fallback) | High |
| `/alerts/{id}` | GET | ✅ Implemented (mock fallback) | High |
| `/alerts/{id}` | PATCH | ✅ Implemented (mock fallback) | Medium |
| `/dashboard/stats` | GET | ✅ Implemented (mock data) | High |
| `/metrics/system` | GET | ✅ Implemented (mock data) | High |
| `/devices` | GET | ✅ Implemented (mock data) | High |
| `/devices/{id}` | GET | ✅ Implemented (mock data) | Medium |
| `/devices/{id}/isolate` | POST | ✅ Implemented (mock data) | Medium |
| `/network/flows` | GET | ✅ Implemented (mock data) | High |
| `/network/stats` | GET | ✅ Implemented (mock data) | Medium |
| `/models/metrics` | GET | ✅ Implemented (mock data) | Medium |
| `/models/train` | POST | ✅ Implemented (mock data) | Low |
| `/models/train/{id}` | GET | ✅ Implemented (mock data) | Low |
| `/models/train` | GET | ✅ Implemented (mock data) | Low |
| `/models/versions` | GET | ✅ Implemented (mock data) | Low |
| `/models/deploy/{version}` | POST | ✅ Implemented (mock data) | Low |

---

## Integration Notes

1. **URL Prefix:** Backend routes are prefixed with `/api` to match frontend expectations

2. **Data Sources:** All endpoints implemented with mock data fallbacks for development/testing:
   - **Database Unavailable:** Returns mock data when MongoDB not connected
   - **Production:** Connects to real data sources when available
   - **Graceful Degradation:** System works with or without external dependencies

3. **Mock Data Strategy:** Mock data includes realistic values and metadata to support frontend development:
   - Alerts: Sample threat detections with scores and timestamps
   - Devices: Mock device inventory with status and risk scores
   - Network: Generated flow data with anomaly scores
   - Metrics: Simulated system performance data

4. **Real-time Updates:** Consider implementing WebSocket connections for real-time dashboard updates

5. **Pagination:** Implemented for devices and alerts endpoints

6. **Error Handling:** Robust error handling with fallback to mock data when services unavailable

---

## Testing

Use these curl commands to test endpoints:

```bash
# Health check
curl http://localhost:8000/health

# Get alerts
curl "http://localhost:8000/alerts?limit=10"

# Get dashboard stats (when implemented)
curl http://localhost:8000/dashboard/stats
```

---

## Version History

- **v1.0.0** - Initial API specification with basic alerts
- **v1.1.0** - Full API implementation with mock data fallbacks
  - ✅ Complete alerts API (GET /alerts, GET /alerts/{id})
  - ✅ Dashboard statistics API (GET /dashboard/stats)
  - ✅ System metrics API (GET /metrics/system)
  - ✅ Device management API (GET /devices, GET /devices/{id}, POST /devices/{id}/isolate)
  - ✅ Network monitoring API (GET /network/flows, GET /network/stats)
  - ✅ AI model management API (GET /models/metrics, POST /models/train, etc.)
  - ✅ Mock data fallbacks for development/testing
  - ✅ CORS enabled for frontend integration
  - ✅ Robust error handling and graceful degradation
- Current implementation: Full API with mock data fallbacks for development
