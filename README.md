# AI-Based Zero-Day Attack Detection System

![Threat Detection Banner](https://i.imgur.com/8Z6XqjV.png)

## Overview

Welcome to the **AI-Based Zero-Day Attack Detection System**, an advanced security solution designed to proactively identify and neutralize never-before-seen cyber threats. This project leverages a sophisticated blend of machine learning and real-time data analysis to detect zero-day exploits by focusing on anomalous system and network behavior, rather than relying on traditional, signature-based methods.

Our system provides a comprehensive, multi-layered defense strategy that monitors, analyzes, and responds to threats in real-time, offering a forward-looking approach to cybersecurity in an era of ever-evolving digital threats.

---

## Key Features

- **Real-Time System Monitoring:** A lightweight agent (`Sysmon`) captures critical system events, including process creation, network connections, and registry modifications, providing deep visibility into endpoint behavior.
- **Intelligent Network Analysis:** The system utilizes `tshark` to perform deep packet inspection, extracting rich features from network traffic to identify suspicious communication patterns.
- **Behavioral Anomaly Detection:** At its core, the system uses an **LSTM Autoencoder** to learn the normal sequences of system events. It flags any deviations from this learned behavior as potential threats, allowing it to catch anomalous activities that traditional tools might miss.
- **Graph-Based Threat Hunting:** A **Graph Neural Network (GNN)** models the network as a dynamic graph of interconnected devices. This allows the system to identify unusual lateral movements, suspicious connections, and other complex attack patterns that are invisible to endpoint-only analysis.
- **Automated Threat Scoring:** An intelligent **Ensemble Scorer** combines the outputs of the LSTM and GNN models into a single, actionable threat score, prioritizing the most critical events for security teams.
- **AI-Powered Response Engine:** When a high-threat event is detected, the system automatically triggers a response, such as sending detailed alerts to security teams via webhooks (e.g., to Slack) and logging the event for further analysis and model retraining.
- **Full-Stack Dashboard:** A modern **React/TypeScript frontend** with real-time threat visualization, interactive charts, and comprehensive monitoring capabilities.
- **Visualization-Ready API:** A built-in **FastAPI backend** serves the processed threat intelligence data, making it easy to connect a frontend dashboard (e.g., React, Kibana) for visualizing alerts, device risk levels, and attack timelines.

---

## System Architecture

The project is built on a modular, scalable architecture that separates data collection, processing, and analysis into distinct components. This design ensures that the system is both high-performing and easy to maintain.

![System Architecture Diagram](https://i.imgur.com/your-architecture-diagram.png) 
*(Note: A placeholder for a detailed architecture diagram)*

The high-level workflow is as follows:

1.  **Data Collection:** `Sysmon` and `tshark` collectors capture system and network data in real-time.
2.  **Preprocessing:** Raw logs are passed through dedicated preprocessing scripts (`preprocess_sysmon.py`, `preprocess_tshark.py`) to be cleaned and structured.
3.  **Feature Engineering:** The structured data is then fed into the feature engineering pipeline, which extracts meaningful features for the ML models.
4.  **ML Inference:** The feature sets are analyzed by the **LSTM Autoencoder** and **GNN**, which generate anomaly scores.
5.  **Threat Scoring:** The individual model scores are combined by the **Ensemble Scorer** to produce a final threat score.
6.  **Response:** The **Response Engine** evaluates the threat score and, if it exceeds the configured threshold, triggers an automated alert.
7.  **Data Serving:** The results and alerts are stored in a database and made available through the **Dashboard API**.

For a deeper dive into the architecture, please see the [**`docs/ARCHITECTURE.md`**](docs/ARCHITECTURE.md) file.

---

## Getting Started

### Prerequisites

- Python 3.8+
- PyTorch
- `tshark` (part of the Wireshark installation)
- MongoDB (for the Dashboard API)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/ai-zero-day-detection.git
    cd ai-zero-day-detection
    ```

2.  **Install the required Python packages:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up your environment:**
    - Ensure `tshark` is in your system's PATH.
    - Make sure your MongoDB instance is running.

### Quick Start: Running the Pipeline

1.  **Preprocess Your Data:**
    - Place your raw Sysmon logs in `data/raw/sysmon/` and your tshark logs in `data/raw/network/`.
    - Run the preprocessing scripts:
      ```bash
      python src/preprocessing/preprocess_sysmon.py --input data/raw/sysmon/your_sysmon_logs.csv --output data/processed/sysmon_processed.csv
      python src/preprocessing/preprocess_tshark.py --input-dir data/raw/network/ --output data/processed/tshark_processed.csv
      ```

2.  **Train the Models:**
    - Follow the detailed guide in [**`docs/MODEL_TRAINING.md`**](docs/MODEL_TRAINING.md) to train the LSTM and GNN models on your processed data.

3.  **Run the Inference and Dashboard API:**
    - Once the models are trained, you can start the real-time inference pipeline and the dashboard API. See the [**`API_GUIDE.md`**](docs/API_GUIDE.md) for instructions.

### Full Stack Deployment with Docker

For a complete development environment with both backend and frontend:

1.  **Start all services:**
    ```bash
    docker-compose up --build
    ```

2.  **Access the applications:**
    - **Frontend Dashboard:** http://localhost:3000
    - **Backend API:** http://localhost:8000
    - **API Documentation:** http://localhost:8000/docs

3.  **Stop the services:**
    ```bash
    docker-compose down
    ```

### Development Setup

For local development without Docker:

1.  **Backend Setup:**
    ```bash
    # Install Python dependencies
    pip install -r requirements.txt

    # Start MongoDB (if not using Docker)
    mongod

    # Start the API server
    cd src/dashboard_api
    uvicorn app:app --reload --host 0.0.0.0 --port 8000
    ```

2.  **Frontend Setup:**
    ```bash
    # Install Node.js dependencies
    cd aegis-zero
    npm install

    # Start the development server
    npm run dev
    ```

The frontend will be available at http://localhost:5173 (Vite dev server) and will proxy API requests to http://localhost:8000.

---

## Documentation

This project is extensively documented to help developers and users get the most out of it.

- **[Architecture Deep Dive](docs/ARCHITECTURE.md):** A detailed look at the system's design and components.
- **[Data Pipeline Guide](docs/DATA_PIPELINE.md):** An explanation of how data flows through the system.
- **[Model Training Guide](docs/MODEL_TRAINING.md):** Instructions on how to train the ML models.
- **[API Guide](docs/API_GUIDE.md):** Documentation for the dashboard API endpoints.

---

## Contributing

We welcome contributions to the AI-Based Zero-Day Attack Detection System! If you're interested in helping, please see our `CONTRIBUTING.md` file for guidelines on how to get started.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
