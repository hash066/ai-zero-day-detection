# 🚀 AI Zero-Day Detection System - Production Deployment Guide

## 📋 System Overview

The AI Zero-Day Detection System is a comprehensive cybersecurity platform that uses machine learning to detect zero-day attacks in real-time. The system processes Sysmon logs and network traffic to identify anomalous behavior patterns.

### 🏗️ Architecture Components

- **API Layer**: FastAPI-based REST API with 18 endpoints
- **ML Engine**: LSTM Autoencoder for temporal anomaly detection
- **Data Pipeline**: Real-time Sysmon and network data collection
- **Streaming Analytics**: Kafka-based event processing
- **Incident Response**: Automated threat mitigation
- **Monitoring**: Prometheus/Grafana dashboards
- **Storage**: MongoDB for persistence, Redis for caching

---

## 🔧 Quick Start (Development)

### Prerequisites
```bash
# Required software
- Python 3.8+
- Docker & Docker Compose
- Git

# Optional (for full functionality)
- MongoDB (if not using Docker)
- Kafka (if not using Docker)
- Sysmon (Windows only)
- Wireshark/TShark (for network capture)
```

### 1. Clone and Setup
```bash
git clone https://github.com/your-org/ai-zero-day-detection.git
cd ai-zero-day-detection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env  # or your preferred editor
```

### 3. Start Development Environment
```bash
# Start core services (API + basic pipeline)
docker-compose up -d mongodb kafka api

# Or start everything
docker-compose up -d
```

### 4. Test the System
```bash
# Test API health
curl http://localhost:8000/health

# Test real threat detection
python test_real_detection.py

# Run integration tests
python -m pytest tests/test_integration.py -v
```

---

## 🏭 Production Deployment

### Option 1: Docker Compose (Recommended)

#### 1. Production Environment Setup
```bash
# Create production environment file
cp .env .env.prod
# Edit .env.prod with production values

# Set production environment
export COMPOSE_ENV_FILE=.env.prod
```

#### 2. Deploy Production Stack
```bash
# Start production environment
docker-compose -f docker-compose.prod.yml up -d

# Check service health
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f api
```

#### 3. Scale Services (Optional)
```bash
# Scale streaming processors
docker-compose -f docker-compose.prod.yml up -d --scale streaming_processor=3

# Scale data collectors
docker-compose -f docker-compose.prod.yml up -d --scale sysmon_collector=2
```

### Option 2: Kubernetes Deployment

#### 1. Apply Kubernetes Manifests
```bash
# Deploy to Kubernetes cluster
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n ai-zero-day
kubectl get services -n ai-zero-day
```

#### 2. Configure Ingress
```bash
# Update ingress configuration
kubectl apply -f k8s/ingress.yml

# Get external IP
kubectl get ingress -n ai-zero-day
```

### Option 3: Manual Installation

#### 1. System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip mongodb kafka tshark

# CentOS/RHEL
sudo yum install -y python3 python3-pip mongodb kafka tshark

# macOS
brew install python3 mongodb kafka tshark
```

#### 2. Service Configuration
```bash
# MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Kafka
# Follow Kafka installation guide
# Start Zookeeper and Kafka services

# Redis (optional)
sudo systemctl start redis
sudo systemctl enable redis
```

#### 3. Application Deployment
```bash
# Install Python dependencies
pip install -r requirements.txt

# Train ML models (if needed)
python src/training/train_lstm.py --data data/processed/training_features.csv

# Start API server
uvicorn src.dashboard_api.app:app --host 0.0.0.0 --port 8000

# Start data collectors (in separate terminals)
python -m src.collectors.live_collector  # For live data collection

# Start streaming processor
python -m src.streaming.kafka_consumer_service
```

---

## ⚙️ Configuration

### Environment Variables

#### Database Configuration
```bash
MONGO_CONNECTION_STRING=mongodb://admin:password@localhost:27017/zero_day_detector
DATABASE_NAME=zero_day_detector
REDIS_URL=redis://localhost:6379
```

#### API Configuration
```bash
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=false
SECRET_KEY=your-production-secret-key
```

#### ML Model Configuration
```bash
LSTM_MODEL_PATH=trained_models/lstm
GNN_MODEL_PATH=trained_models/gnn
ENSEMBLE_MODEL_PATH=trained_models/ensemble
```

#### Streaming Configuration
```bash
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPIC_SYSMON=sysmon_events
KAFKA_TOPIC_NETWORK=network_flows
STREAMING_BATCH_SIZE=10
STREAMING_BATCH_TIMEOUT=5.0
```

#### Incident Response Configuration
```bash
AUTO_RESPONSE_ENABLED=false
HIGH_SEVERITY_AUTO_ISOLATE=false
ALERT_WEBHOOK_URL=https://your-webhook-url
SLACK_WEBHOOK_URL=https://hooks.slack.com/your-slack-webhook
```

### Model Training

#### Train LSTM Model
```bash
# Generate training data
python generate_training_data.py

# Train model
python src/training/train_lstm.py \
  --data data/processed/training_features.csv \
  --epochs 50 \
  --batch-size 32 \
  --output trained_models/lstm
```

#### Train GNN Model (Optional)
```bash
python src/training/train_gnn.py \
  --data data/graphs/ \
  --epochs 100 \
  --output trained_models/gnn
```

---

## 📊 Monitoring & Observability

### Health Checks
```bash
# API Health
curl http://localhost:8000/health

# Service Status
curl http://localhost:8000/api/status

# Metrics
curl http://localhost:8000/api/metrics
```

### Grafana Dashboards
- **URL**: http://localhost:3000
- **Default Credentials**: admin/admin
- **Dashboards**:
  - AI Detection Metrics
  - System Performance
  - Threat Intelligence

### Prometheus Metrics
- **URL**: http://localhost:9090
- **Metrics Endpoints**:
  - `/metrics` on API service
  - `/metrics` on streaming processors

### ELK Stack (Optional)
- **Kibana**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200
- **Logstash**: Processes application logs

---

## 🔒 Security Configuration

### API Security
```bash
# Enable JWT authentication
JWT_SECRET_KEY=your-256-bit-secret
JWT_EXPIRATION_HOURS=24

# CORS configuration (restrict in production)
CORS_ORIGINS=https://yourdomain.com
```

### Network Security
```bash
# Firewall rules (example for iptables)
sudo iptables -A INPUT -p tcp --dport 8000 -s your.trusted.network -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9092 -s your.trusted.network -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 27017 -s your.trusted.network -j ACCEPT
```

### Data Encryption
```bash
# MongoDB encryption
# Configure MongoDB with TLS/SSL
# Enable field-level encryption for sensitive data

# Kafka encryption
# Configure SSL for Kafka brokers
# Use SASL authentication
```

---

## 🚨 Incident Response Setup

### Automated Response Configuration
```bash
# Enable automated responses (use with caution)
AUTO_RESPONSE_ENABLED=true
HIGH_SEVERITY_AUTO_ISOLATE=true
CRITICAL_SEVERITY_AUTO_SHUTDOWN=false

# Response timeouts
ISOLATION_DURATION_MINUTES=30
MAX_CONCURRENT_RESPONSES=10
```

### Alert Integration
```bash
# Webhook alerts
ALERT_WEBHOOK_URL=https://your-security-webhook

# Slack alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Email alerts
ALERT_EMAIL_RECIPIENTS=security@yourcompany.com,admin@yourcompany.com
```

### Manual Response Procedures
1. **Low Severity**: Log and monitor
2. **Medium Severity**: Alert security team
3. **High Severity**: Isolate affected systems
4. **Critical Severity**: Emergency response procedures

---

## 📈 Scaling & Performance

### Horizontal Scaling
```bash
# Scale API instances
docker-compose -f docker-compose.prod.yml up -d --scale api=3

# Scale streaming processors
docker-compose -f docker-compose.prod.yml up -d --scale streaming_processor=5

# Scale data collectors
docker-compose -f docker-compose.prod.yml up -d --scale sysmon_collector=2
docker-compose -f docker-compose.prod.yml up -d --scale network_collector=2
```

### Database Scaling
```bash
# MongoDB replica set
# Configure MongoDB with replica set for high availability

# Redis cluster
# Set up Redis cluster for distributed caching
```

### Performance Tuning
```yaml
# API performance settings
WORKERS: 4
MAX_REQUESTS: 1000
MAX_REQUESTS_JITTER: 50

# Streaming performance
BATCH_SIZE: 50
BATCH_TIMEOUT: 2.0
KAFKA_CONSUMER_THREADS: 3

# ML inference optimization
GPU_ENABLED: true
INFERENCE_BATCH_SIZE: 32
MODEL_CACHE_SIZE: 100
```

---

## 🔄 Backup & Recovery

### Database Backup
```bash
# MongoDB backup
docker exec ai_zero_day_mongodb mongodump --out /backup/$(date +%Y%m%d_%H%M%S)

# Automated backup script
0 2 * * * docker exec ai_zero_day_mongodb mongodump --out /backup/$(date +%Y%m%d)
```

### Model Backup
```bash
# Backup trained models
tar -czf models_backup_$(date +%Y%m%d).tar.gz trained_models/

# Automated model backup
0 3 * * * tar -czf /backup/models_$(date +%Y%m%d).tar.gz trained_models/
```

### Configuration Backup
```bash
# Backup configurations
cp .env .env.backup.$(date +%Y%m%d)
cp config.yaml config.yaml.backup.$(date +%Y%m%d)
```

---

## 🐛 Troubleshooting

### Common Issues

#### API Won't Start
```bash
# Check logs
docker-compose logs api

# Check dependencies
python -c "import fastapi, uvicorn, pymongo"

# Check port availability
netstat -tlnp | grep 8000
```

#### Database Connection Failed
```bash
# Check MongoDB status
docker-compose ps mongodb

# Check connection string
docker exec -it ai_zero_day_mongodb mongo --eval "db.stats()"

# Reset database
docker-compose restart mongodb
```

#### ML Model Loading Failed
```bash
# Check model files exist
ls -la trained_models/lstm/

# Check model compatibility
python -c "import torch; print(torch.__version__)"

# Retrain model
python src/training/train_lstm.py --data data/processed/training_features.csv
```

#### Kafka Connection Issues
```bash
# Check Kafka status
docker-compose ps kafka

# Check topics
docker exec ai_zero_day_kafka kafka-topics --list --bootstrap-server localhost:9092

# Reset Kafka
docker-compose restart zookeeper kafka
```

### Log Analysis
```bash
# View application logs
docker-compose logs -f api

# View streaming logs
docker-compose logs -f streaming_processor

# View collector logs
docker-compose logs -f sysmon_collector network_collector
```

---

## 📚 API Documentation

### Interactive API Docs
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI Schema**: http://localhost:8000/openapi.json

### Key Endpoints

#### Alerts Management
```http
GET    /api/alerts          # List alerts
POST   /api/alerts          # Create alert
GET    /api/alerts/{id}     # Get alert details
PATCH  /api/alerts/{id}     # Update alert status
DELETE /api/alerts/{id}     # Delete alert
```

#### Threat Detection
```http
POST   /api/detect          # Real-time threat detection
GET    /api/models          # ML model status
POST   /api/models/retrain  # Retrain models
```

#### System Monitoring
```http
GET    /api/metrics         # System metrics
GET    /api/health          # Health check
GET    /api/status          # Service status
```

---

## 🤝 Support & Contributing

### Getting Help
- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

### Development
```bash
# Run tests
python -m pytest tests/ -v

# Run linting
flake8 src/ tests/

# Format code
black src/ tests/

# Type checking
mypy src/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Important Notes

### Security Considerations
- Change default passwords in production
- Use strong secrets for JWT and encryption
- Restrict network access to services
- Regularly update dependencies
- Monitor for security vulnerabilities

### Performance Considerations
- Scale services based on load
- Monitor resource usage
- Optimize ML model inference
- Use appropriate hardware for ML workloads

### Operational Considerations
- Set up monitoring and alerting
- Implement backup strategies
- Plan for disaster recovery
- Document operational procedures
- Train security team on system usage

---

**🎉 Your AI Zero-Day Detection System is now ready for production deployment!**

For additional support or questions, please refer to the documentation or create an issue on GitHub.
