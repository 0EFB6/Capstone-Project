# Capstone Project - Machine Learning-Based Network Intrusion Detection System

A real-time, ML-powered Intrusion Detection System (IDS) for detecting DoS attacks in cloud network environments. This system leverages XGBoost classifiers trained on the CIC-IDS2018 dataset to identify malicious network traffic with decent accuracy in AWS infrastructure.

## 🎯 Overview

This capstone project implements an end-to-end machine learning-based network intrusion detection system capable of identifying DDoS attacks in real-time. The system processes live network traffic, extracts flow-based features, and uses trained ensemble models to classify traffic as benign or malicious.

### Key Capabilities

- **Real-time Detection**: Live packet capture and analysis using Suricata
- **Binary Classification**: Benign vs Malicious traffic identification
- **Multi-Attack Detection**: Supports detection of various DDoS attack types:
  - HTTP GET Flood (HOIC)
  - Slowloris
  - TCP SYN Flood
- **AWS Deployment**: Production-ready deployment on EC2 instances
- **Comprehensive Evaluation**: Ground truth labeling and performance metrics

## ✨ Features

### Detection Pipeline

- **Packet Capture**: Real-time traffic monitoring using Suricata on the enX0 network interface
- **Flow Aggregation**: Bidirectional flow construction with timeout management
- **Feature Extraction**: 35 flow-based features aligned with CIC-IDS2018
- **ML Inference**: XGBoost
- **Alert Generation**: Real-time logging and simple dashboard visualization

### Model Characteristics

- **Algorithms**: XGBoost
- **Training Data**: CIC-IDS2018 dataset (5 CSV files, 4M+ rows)
- **Features**: 35 network flow features (packet statistics, timing, flags)

### Evaluation Framework

- **Ground Truth Generation**: Automated attack simulation with timestamp logging
- **Multi-Source Support**: Concurrent attacker scenario evaluation
- **IP Matching**: Source IP-based prediction matching
- **Metrics**: Accuracy, Precision, Recall, F1-Score, Confusion Matrix

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA PIPELINE                                 │
├─────────────────────────────────────────────────────────────────┤
│ CIC-IDS2018 Dataset → Data Cleaning → Preprocessing →           │
│ Feature Extraction → Class Balancing → Train/Val/Test Split     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  MODEL TRAINING                                  │
├─────────────────────────────────────────────────────────────────┤
│ XGBoost + Random Forest → Hyperparameter Tuning →               │
│ Cross-Validation → Model Selection → Save Best Model            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              DETECTION PIPELINE (AWS EC2)                        │
├─────────────────────────────────────────────────────────────────┤
│ Live Traffic → Packet Capture (Suricata) → Flow Aggregation →   │
│ Feature Extraction → ML Inference → Classification →             │
│ Alert Logging → Dashboard Display                               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              EVALUATION FRAMEWORK                                │
├─────────────────────────────────────────────────────────────────┤
│ Attacker EC2 → Traffic Generation → Ground Truth CSV →          │
│ Victim EC2 → Predictions CSV → Evaluation Script →              │
│ Confusion Matrix → Performance Metrics → Results JSON           │
└─────────────────────────────────────────────────────────────────┘
```

### AWS Infrastructure

- **VPC Subnet**: Isolated testing environment
- **Attacker EC2 Instances**: Traffic generation (2 concurrent sources supported)
- **Victim EC2 Instance**: IDS deployment with live traffic monitoring
- **Attack Types**: Slowloris, TCP SYN Flood, HTTP Flood (HOIC), ICMP Flood, HTTP Browsing (Benign)

See [Architecture_Diagram_Overview.png](Architecture_Diagram_Overview.png) for detailed system architecture.

## 📊 Dataset

### CIC-IDS2018

The Canadian Institute for Cybersecurity's 2018 Intrusion Detection Evaluation Dataset contains:

- **Total Samples**: 16,000,000+ network flows
- **Features**: 80 flow-based features
- **Attack Types**: 7 categories (DDoS, DoS-Hulk, DoS-Slowloris, DoS-GoldenEye, etc.)
- **Time Span**: 10 days of captured traffic

### Selected Attack Classes

For this project, we focus on binary classification with the following attack types:

- **Benign**: Normal network traffic
- **DDOS attack-HOIC**: High Orbit Ion Cannon floods
- **DoS attacks-Hulk**: HTTP Unbearable Load King
- **SSH-Bruteforce**: SSH credential attacks
- **DoS attacks-GoldenEye**: HTTP DoS via KeepAlive
- **DoS attacks-Slowloris**: Slow HTTP attacks

### Data Preprocessing

1. **Cleaning**: Remove NaN values and duplicate rows
2. **Feature Selection**: 35 relevant network flow features
3. **Label Encoding**: Binary (Benign=0, Malicious=1)
4. **Normalization**: StandardScaler for numerical features
5. **Split**: 70% train, 10% validation, 20% test

## 🧠 Model Training

### Training Pipeline

Run the complete training pipeline in Google Colab or locally:

```bash
jupyter notebook model_training.ipynb
```

### Key Steps

1. **Data Loading**: Load all 5 CIC-IDS2018 CSV files
2. **Preprocessing**: Clean, encode, and normalize features
3. **Feature Engineering**: Extract 35 flow-based features
4. **Model Training**: XGBoost with GPU acceleration
5. **Hyperparameter Tuning**: Grid search with cross-validation
6. **Evaluation**: Generate confusion matrix and classification reports
7. **Model Export**: Save best models as `.pkl` files

### Output Artifacts

```
models/
├── xgboost_final.pkl
├── random_forest_final.pkl
├── scaler.pkl
├── label_encoder.pkl
└── feature_names.json
```

### Inference Parameters

| Parameter | Description | Default | Recommended |
|-----------|-------------|---------|-------------|
| `--model-dir` | Directory containing model files | Required | `/opt/ids/models/` |
| `--interface` | Network interface to monitor | `enX0` | Check with `ip addr` |
| `--threshold` | Malicious probability threshold | `0.63` | `0.5-0.7` |
| `--eval` | Enable evaluation logging | `False` | `True` for testing |
| `--eval-dir` | Evaluation output directory | `/opt/ids/evaluation` | Custom path |

### Real-Time Dashboard

Once running, the IDS displays:

```
============================================================
IDS INFERENCE SYSTEM
📊 EVALUATION MODE - Logging predictions to CSV
============================================================

Runtime: 5m 23s | Time: 14:32:17

TRAFFIC SUMMARY:
  Total Processed: 1,234,567
  Benign:          1,100,000 (89.1%)
  Malicious:       134,567 (10.9%)

  Predictions Logged: 1,234,567

ATTACK BREAKDOWN:
  http_flood_hoic          : 45,123 (33.6%)
  slowloris                : 38,901 (28.9%)
  syn_flood                : 50,543 (37.5%)

============================================================
Press Ctrl+C to stop
============================================================
```

## 📈 Evaluation

### Generate Ground Truth

Run on attacker instances:

```bash
# Quick test (~5 minutes)
./experiment_attacker_script.sh quick

# Standard test (~30 minutes)
./experiment_attacker_script.sh standard

# Full test (~2 hours)
./experiment_attacker_script.sh full
```

Output: `eval_YYYYMMDD_HHMMSS_ground_truth.csv`

### Collect Predictions

Predictions are automatically logged during IDS operation:

- Location: `/opt/ids/evaluation/YYYYMMDD_HHMMSS_predictions.csv`
- Format: Timestamp, Flow ID, Source IP, Destination IP, Predicted Label, Confidence

### Run Evaluation Script

```bash
# Run evaluation with multiple sources
python3 evaluation.py \
    --ground-truth /opt/ids/evaluation/eval_*_ground_truth.csv \
    --predictions /opt/ids/evaluation/20251207_143022_predictions.csv \
    --output-dir ./results

# With IP matching disabled (time-only)
python3 evaluation.py \
    -g eval_attacker1_ground_truth.csv eval_attacker2_ground_truth.csv \
    -p predictions.csv \
    --no-ip-matching
```

### Evaluation Output

```
══════════════════════════════════════════════════════════════════
  IDS MODEL EVALUATION
  Binary Classification: Benign vs Malicious
  Multi-Source Mode: 2 attack sources
══════════════════════════════════════════════════════════════════

📊 CONFUSION MATRIX
                 Predicted Benign  Predicted Malicious
Actual Benign            142,567                8,234
Actual Malicious           2,891              156,308

📈 PERFORMANCE METRICS
  Accuracy:   96.41%
  Precision:  95.00%
  Recall:     98.18%
  F1-Score:   96.56%

✅ EVALUATION COMPLETE
```

Generates:
- `eval_YYYYMMDD_HHMMSS_labeled_predictions.csv`: Matched predictions with ground truth
- `eval_YYYYMMDD_HHMMSS_results.json`: Complete metrics in JSON format

## 🎯 Results

### Laboratory Performance (Test Set)

Training on CIC-IDS2018 dataset with 70/10/20 split:

| Metric | XGBoost |
|--------|---------|
| **Accuracy** | 95.33% | 
| **Precision** | 95.95% |
| **Recall** | 95.33% |
| **F1-Score** | 95.38% | 

### Real-World Performance (AWS Deployment)

2-hour Live traffic evaluation with ground truth labeling:

| Metric | XGBoost |
|--------|---------|
| **Accuracy** | 83.34% | 
| **Precision** | 96.20% |
| **Recall** | 71.11% |
| **F1-Score** | 81.77% |
| **False Positive Rate** | 3.11% | 
| **False Negative Rate** | 28.89% |

## 🙏 Acknowledgments

- **Dataset**: [CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) by Canadian Institute for Cybersecurity
- **Libraries**: Scapy, XGBoost, scikit-learn, pandas, numpy
- **Infrastructure**: AWS EC2, AWS VPC, AWS Security Groups
- **Institution**: Faculty of Engineering and Technology, Sunway University

## 📧 Contact

**Project Author**: [Wilson Chang]
- Email: 23026149@imail.sunway.edu.my

---