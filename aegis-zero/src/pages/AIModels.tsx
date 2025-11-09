import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Brain, TrendingUp, RefreshCw } from 'lucide-react';
import { Chart } from '../components/Chart';
import { mockModelMetrics, mockDashboardStats } from '../services/mockData';
import type { ModelMetrics } from '../types';

export function AIModels() {
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [isTraining, setIsTraining] = useState(false);

  useEffect(() => {
    setMetrics(mockModelMetrics());
  }, []);

  const handleRetrain = () => {
    setIsTraining(true);
    // Simulate training
    setTimeout(() => {
      setIsTraining(false);
      setMetrics({
        ...metrics!,
        lastTrained: new Date().toISOString(),
      });
    }, 3000);
  };

  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  const trendsData = mockDashboardStats().trendsData.anomalyScore;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-dark-50 mb-2">AI Models</h1>
          <p className="text-dark-400">Monitor and manage ML models</p>
        </div>
        <button
          onClick={handleRetrain}
          disabled={isTraining}
          className="btn-primary flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${isTraining ? 'animate-spin' : ''}`} />
          {isTraining ? 'Training...' : 'Retrain Models'}
        </button>
      </div>

      {/* Model Performance Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Accuracy" value={`${(metrics.accuracy * 100).toFixed(1)}%`} />
        <MetricCard label="Precision" value={`${(metrics.precision * 100).toFixed(1)}%`} />
        <MetricCard label="Recall" value={`${(metrics.recall * 100).toFixed(1)}%`} />
        <MetricCard label="F1 Score" value={`${(metrics.f1Score * 100).toFixed(1)}%`} />
      </div>

      {/* Model Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <ModelCard
          name="LSTM Autoencoder"
          description="Temporal anomaly detection for system behavior sequences"
          status="active"
          accuracy={94.7}
        />
        <ModelCard
          name="Graph Neural Network"
          description="Network topology analysis and connection pattern detection"
          status="active"
          accuracy={92.3}
        />
        <ModelCard
          name="Ensemble Scorer"
          description="Combines LSTM and GNN outputs for final threat scoring"
          status="active"
          accuracy={95.6}
        />
      </div>

      {/* Performance Trend */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-dark-50">Detection Performance Trend</h2>
          <div className="flex items-center gap-2 text-sm text-dark-400">
            <TrendingUp className="w-4 h-4" />
            <span>Last 24 hours</span>
          </div>
        </div>
        <Chart data={trendsData} color="#f59e0b" height={300} />
      </motion.div>

      {/* Training Information */}
      <div className="card">
        <h2 className="text-lg font-semibold text-dark-50 mb-4">Training Information</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <InfoItem label="Last Trained" value={new Date(metrics.lastTrained).toLocaleString()} />
          <InfoItem label="Total Predictions" value={metrics.totalPredictions.toLocaleString()} />
          <InfoItem label="Model Version" value="v2.3.1" />
          <InfoItem label="Training Dataset" value="15,234 samples" />
        </div>
      </div>

      {/* Model Architecture */}
      <div className="card">
        <h2 className="text-lg font-semibold text-dark-50 mb-4">Model Architecture</h2>
        <div className="space-y-4">
          <ArchitectureItem
            title="Input Layer"
            description="92 behavioral features extracted from network traffic and system logs"
          />
          <ArchitectureItem
            title="LSTM Autoencoder"
            description="Bidirectional LSTM with attention mechanism for temporal pattern analysis"
          />
          <ArchitectureItem
            title="Graph Neural Network"
            description="GAT-based network topology analyzer with 3 layers and 4 attention heads"
          />
          <ArchitectureItem
            title="Ensemble Layer"
            description="Neural network combiner for final threat score prediction"
          />
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="card">
      <div className="text-sm text-dark-400 mb-1">{label}</div>
      <div className="text-2xl font-bold text-dark-50">{value}</div>
    </div>
  );
}

function ModelCard({
  name,
  description,
  status,
  accuracy,
}: {
  name: string;
  description: string;
  status: 'active' | 'training' | 'inactive';
  accuracy: number;
}) {
  const statusConfig = {
    active: { color: 'bg-green-500', label: 'Active' },
    training: { color: 'bg-yellow-500', label: 'Training' },
    inactive: { color: 'bg-gray-500', label: 'Inactive' },
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="card hover:shadow-xl transition-all duration-200"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="p-2 bg-primary-600/10 rounded-lg">
          <Brain className="w-5 h-5 text-primary-400" />
        </div>
        <div className="flex items-center gap-1.5">
          <div className={`w-2 h-2 rounded-full ${statusConfig[status].color}`} />
          <span className="text-xs text-dark-400">{statusConfig[status].label}</span>
        </div>
      </div>
      <h3 className="font-semibold text-dark-50 mb-2">{name}</h3>
      <p className="text-sm text-dark-400 mb-4">{description}</p>
      <div className="flex items-center justify-between pt-3 border-t border-dark-800">
        <span className="text-xs text-dark-500">Accuracy</span>
        <span className="text-lg font-bold text-green-500">{accuracy}%</span>
      </div>
    </motion.div>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-sm text-dark-400 mb-1">{label}</span>
      <span className="text-lg font-medium text-dark-50">{value}</span>
    </div>
  );
}

function ArchitectureItem({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 p-4 bg-dark-800 rounded-lg">
      <div className="w-2 h-2 rounded-full bg-primary-600 mt-2" />
      <div className="flex-1">
        <h4 className="font-medium text-dark-50 mb-1">{title}</h4>
        <p className="text-sm text-dark-400">{description}</p>
      </div>
    </div>
  );
}
