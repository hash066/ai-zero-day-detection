import type { 
  ThreatAlert, 
  SystemMetrics, 
  Device, 
  NetworkFlow, 
  ModelMetrics, 
  DashboardStats 
} from '../types';

// API Base URL - Replace with your actual backend URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

class ApiService {
  private async fetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers,
        },
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // Dashboard Stats
  async getDashboardStats(): Promise<DashboardStats> {
    return this.fetch<DashboardStats>('/dashboard/stats');
  }

  // Threat Alerts
  async getAlerts(params?: { limit?: number; severity?: string }): Promise<ThreatAlert[]> {
    const queryParams = new URLSearchParams(params as any).toString();
    return this.fetch<ThreatAlert[]>(`/alerts?${queryParams}`);
  }

  async getAlertById(id: string): Promise<ThreatAlert> {
    return this.fetch<ThreatAlert>(`/alerts/${id}`);
  }

  async updateAlertStatus(id: string, status: ThreatAlert['status']): Promise<ThreatAlert> {
    return this.fetch<ThreatAlert>(`/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  // System Metrics
  async getSystemMetrics(): Promise<SystemMetrics> {
    return this.fetch<SystemMetrics>('/metrics/system');
  }

  // Devices
  async getDevices(): Promise<Device[]> {
    return this.fetch<Device[]>('/devices');
  }

  async getDeviceById(id: string): Promise<Device> {
    return this.fetch<Device>(`/devices/${id}`);
  }

  async isolateDevice(id: string): Promise<Device> {
    return this.fetch<Device>(`/devices/${id}/isolate`, {
      method: 'POST',
    });
  }

  // Network Flows
  async getNetworkFlows(limit: number = 100): Promise<NetworkFlow[]> {
    return this.fetch<NetworkFlow[]>(`/network/flows?limit=${limit}`);
  }

  // Model Metrics
  async getModelMetrics(): Promise<ModelMetrics> {
    return this.fetch<ModelMetrics>('/models/metrics');
  }

  async trainModel(): Promise<{ status: string; message: string }> {
    return this.fetch('/models/train', {
      method: 'POST',
    });
  }
}

export const apiService = new ApiService();
