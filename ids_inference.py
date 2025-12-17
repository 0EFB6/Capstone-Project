#!/usr/bin/env python3
"""
Real-time IDS Inference Engine
"""

import sys
import time
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict, deque
import threading
import json
import os
import logging
import csv

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("❌ Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# =============================================================================
# PREDICTION LOGGER FOR EVALUATION
# =============================================================================

class PredictionLogger:
    """
    Thread-safe CSV logger for model predictions.
    Logs each prediction with timestamp for evaluation against ground truth.
    """

    def __init__(self, output_dir="/opt/ids/evaluation", enabled=True):
        self.enabled = enabled
        if not enabled:
            return

        self.output_dir = output_dir
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = os.path.join(output_dir, f"{self.session_id}_predictions.csv")
        self.lock = threading.Lock()
        self.prediction_count = 0

        os.makedirs(output_dir, exist_ok=True)

        with open(self.csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp',
                'flow_id',
                'src_ip',
                'dst_ip',
                'src_port',
                'dst_port',
                'protocol',
                'predicted_label',
                'predicted_attack_type',
                'confidence',
                'benign_prob',
                'malicious_prob'
            ])

        print(f"📝 Evaluation logging enabled: {self.csv_path}")

    def log_prediction(self, flow_key, flow, predicted_label, attack_type,
                       benign_prob, malicious_prob):
        """
        Log a single prediction for evaluation.

        Args:
            flow_key: Tuple (src_ip, dst_ip, src_port, dst_port, protocol)
            flow: Flow dict with metadata
            predicted_label: Binary label - 'Benign' or 'Malicious'
            attack_type: Specific attack type (or 'Benign' if benign)
            benign_prob: Probability of benign (0-1)
            malicious_prob: Probability of malicious (0-1)
        """
        if not self.enabled:
            return

        timestamp = datetime.now().isoformat()
        flow_id = f"{flow_key[0]}_{flow_key[1]}_{flow_key[2]}_{flow_key[3]}_{flow_key[4]}"

        with self.lock:
            try:
                with open(self.csv_path, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        timestamp,
                        flow_id,
                        flow['dst_ip'],
                        flow['dst_ip'],
                        flow['src_port'],
                        flow['dst_port'],
                        flow['protocol'],
                        predicted_label,           # Benign or Malicious
                        attack_type,               # Specific type
                        f"{malicious_prob:.4f}",   # Confidence = malicious prob for attacks
                        f"{benign_prob:.4f}",
                        f"{malicious_prob:.4f}"
                    ])
                self.prediction_count += 1
            except Exception as e:
                print(f"⚠️ Logging error: {e}")

    def get_stats(self):
        """Get logging statistics"""
        if not self.enabled:
            return {'enabled': False}
        return {
            'enabled': True,
            'session_id': self.session_id,
            'csv_path': self.csv_path,
            'prediction_count': self.prediction_count
        }

    def finalize(self):
        """Print logging summary on shutdown"""
        if not self.enabled:
            return

        print(f"\n📊 Evaluation Logging Summary")
        print(f"   Session ID: {self.session_id}")
        print(f"   Total predictions logged: {self.prediction_count:,}")
        print(f"   Output file: {self.csv_path}")

# =============================================================================
# FLOW AGGREGATOR
# =============================================================================

class FlowAggregator:
    """Aggregates packets into bidirectional flows"""

    def __init__(self, flow_timeout=120):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.lock = threading.Lock()

    def get_flow_key(self, packet):
        if not packet.haslayer(IP):
            return None

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = 6
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = 17
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = 1
            sport = 0
            dport = 0
        else:
            return None

        if ip_src < ip_dst:
            flow_key = (ip_src, ip_dst, sport, dport, proto)
            direction = 'forward'
        else:
            flow_key = (ip_dst, ip_src, dport, sport, proto)
            direction = 'backward'

        return flow_key, direction

    def add_packet(self, packet):
        try:
            result = self.get_flow_key(packet)
            if result is None:
                return None

            flow_key, direction = result
            timestamp = packet.time

            with self.lock:
                if flow_key not in self.flows:
                    self.flows[flow_key] = {
                        'src_ip': flow_key[0],
                        'dst_ip': flow_key[1],
                        'src_port': flow_key[2],
                        'dst_port': flow_key[3],
                        'protocol': flow_key[4],
                        'start_time': timestamp,
                        'last_seen': timestamp,
                        'fwd_packets': [],
                        'bwd_packets': [],
                        'fwd_iat': [],
                        'bwd_iat': [],
                        'flags': defaultdict(int)
                    }

                flow = self.flows[flow_key]
                flow['last_seen'] = timestamp

                pkt_len = len(packet)

                if direction == 'forward':
                    flow['fwd_packets'].append({
                        'time': timestamp,
                        'length': pkt_len,
                        'header_len': packet[IP].ihl * 4 if packet.haslayer(IP) else 0
                    })

                    if len(flow['fwd_packets']) > 1:
                        iat = timestamp - flow['fwd_packets'][-2]['time']
                        flow['fwd_iat'].append(iat)
                else:
                    flow['bwd_packets'].append({
                        'time': timestamp,
                        'length': pkt_len,
                        'header_len': packet[IP].ihl * 4 if packet.haslayer(IP) else 0
                    })

                    if len(flow['bwd_packets']) > 1:
                        iat = timestamp - flow['bwd_packets'][-2]['time']
                        flow['bwd_iat'].append(iat)

                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    if flags.S: flow['flags']['SYN'] += 1
                    if flags.F: flow['flags']['FIN'] += 1
                    if flags.R: flow['flags']['RST'] += 1
                    if flags.P: flow['flags']['PSH'] += 1
                    if flags.A: flow['flags']['ACK'] += 1

                    if 'init_fwd_win' not in flow and direction == 'forward':
                        flow['init_fwd_win'] = packet[TCP].window
                    if 'init_bwd_win' not in flow and direction == 'backward':
                        flow['init_bwd_win'] = packet[TCP].window

                return flow_key

        except Exception as e:
            pass
        return None

    def get_expired_flows(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        expired = []
        with self.lock:
            keys_to_delete = []
            for flow_key, flow in self.flows.items():
                if current_time - flow['last_seen'] > self.flow_timeout:
                    expired.append((flow_key, flow))
                    keys_to_delete.append(flow_key)

            for key in keys_to_delete:
                del self.flows[key]

        return expired

    def get_all_flows(self):
        """Get all flows (for shutdown processing)"""
        with self.lock:
            flows = list(self.flows.items())
            self.flows.clear()
        return flows

# =============================================================================
# FEATURE EXTRACTOR
# =============================================================================

class FeatureExtractor:
    """Extracts 35 features from flows"""

    FEATURES = [
        'Dst Port', 'Protocol', 'Flow Duration',
        'Tot Fwd Pkts', 'Tot Bwd Pkts',
        'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
        'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
        'Flow Byts/s', 'Flow Pkts/s',
        'Flow IAT Mean', 'Flow IAT Std',
        'Fwd IAT Mean', 'Fwd IAT Std',
        'Fwd Pkts/s', 'Bwd Pkts/s',
        'Pkt Len Mean', 'Pkt Len Std',
        'SYN Flag Cnt', 'FIN Flag Cnt', 'RST Flag Cnt',
        'PSH Flag Cnt', 'ACK Flag Cnt',
        'Down/Up Ratio', 'Pkt Size Avg',
        'Fwd Seg Size Avg', 'Subflow Fwd Pkts', 'Subflow Bwd Pkts',
        'Init Fwd Win Byts', 'Init Bwd Win Byts',
        'Fwd Header Len', 'Bwd Header Len'
    ]

    @staticmethod
    def extract_features(flow):
        try:
            features = {}

            features['Dst Port'] = flow['dst_port']
            features['Protocol'] = flow['protocol']

            duration = flow['last_seen'] - flow['start_time']
            features['Flow Duration'] = int(duration * 1_000_000)

            fwd_pkts = flow['fwd_packets']
            bwd_pkts = flow['bwd_packets']
            features['Tot Fwd Pkts'] = len(fwd_pkts)
            features['Tot Bwd Pkts'] = len(bwd_pkts)

            fwd_lens = [p['length'] for p in fwd_pkts]
            bwd_lens = [p['length'] for p in bwd_pkts]
            all_lens = fwd_lens + bwd_lens

            features['TotLen Fwd Pkts'] = sum(fwd_lens)
            features['TotLen Bwd Pkts'] = sum(bwd_lens)

            features['Fwd Pkt Len Mean'] = np.mean(fwd_lens) if fwd_lens else 0
            features['Fwd Pkt Len Std'] = np.std(fwd_lens) if len(fwd_lens) > 1 else 0
            features['Bwd Pkt Len Mean'] = np.mean(bwd_lens) if bwd_lens else 0
            features['Bwd Pkt Len Std'] = np.std(bwd_lens) if len(bwd_lens) > 1 else 0

            features['Pkt Len Mean'] = np.mean(all_lens) if all_lens else 0
            features['Pkt Len Std'] = np.std(all_lens) if len(all_lens) > 1 else 0
            features['Pkt Size Avg'] = features['Pkt Len Mean']

            if duration > 0:
                features['Flow Byts/s'] = (features['TotLen Fwd Pkts'] + features['TotLen Bwd Pkts']) / duration
                features['Flow Pkts/s'] = (features['Tot Fwd Pkts'] + features['Tot Bwd Pkts']) / duration
                features['Fwd Pkts/s'] = features['Tot Fwd Pkts'] / duration
                features['Bwd Pkts/s'] = features['Tot Bwd Pkts'] / duration
            else:
                features['Flow Byts/s'] = 0
                features['Flow Pkts/s'] = 0
                features['Fwd Pkts/s'] = 0
                features['Bwd Pkts/s'] = 0

            fwd_iat = flow['fwd_iat']
            bwd_iat = flow['bwd_iat']
            all_iat = fwd_iat + bwd_iat

            fwd_iat_us = [iat * 1_000_000 for iat in fwd_iat]
            bwd_iat_us = [iat * 1_000_000 for iat in bwd_iat]
            all_iat_us = [iat * 1_000_000 for iat in all_iat]

            features['Flow IAT Mean'] = np.mean(all_iat_us) if all_iat_us else 0
            features['Flow IAT Std'] = np.std(all_iat_us) if len(all_iat_us) > 1 else 0
            features['Fwd IAT Mean'] = np.mean(fwd_iat_us) if fwd_iat_us else 0
            features['Fwd IAT Std'] = np.std(fwd_iat_us) if len(fwd_iat_us) > 1 else 0

            features['SYN Flag Cnt'] = flow['flags']['SYN']
            features['FIN Flag Cnt'] = flow['flags']['FIN']
            features['RST Flag Cnt'] = flow['flags']['RST']
            features['PSH Flag Cnt'] = flow['flags']['PSH']
            features['ACK Flag Cnt'] = flow['flags']['ACK']

            if features['TotLen Fwd Pkts'] > 0:
                features['Down/Up Ratio'] = features['TotLen Bwd Pkts'] / features['TotLen Fwd Pkts']
            else:
                features['Down/Up Ratio'] = 0

            features['Fwd Seg Size Avg'] = features['Fwd Pkt Len Mean']
            features['Subflow Fwd Pkts'] = features['Tot Fwd Pkts']
            features['Subflow Bwd Pkts'] = features['Tot Bwd Pkts']
            features['Init Fwd Win Byts'] = flow.get('init_fwd_win', 0)
            features['Init Bwd Win Byts'] = flow.get('init_bwd_win', 0)

            fwd_headers = [p['header_len'] for p in fwd_pkts]
            bwd_headers = [p['header_len'] for p in bwd_pkts]
            features['Fwd Header Len'] = sum(fwd_headers)
            features['Bwd Header Len'] = sum(bwd_headers)

            return [features[f] for f in FeatureExtractor.FEATURES]

        except Exception as e:
            return None

# =============================================================================
# THRESHOLD INFERENCE ENGINE
# =============================================================================

class ThresholdInferenceEngine:
    """ML inference with adjustable threshold"""

    def __init__(self, model_dir, malicious_threshold=0.63):
        self.malicious_threshold = malicious_threshold
        print(f"\n{'='*60}")
        print("🔧 LOADING ML MODELS")
        print(f"{'='*60}\n")

        try:
            self.model = joblib.load(os.path.join(model_dir, 'xgboost_model.pkl'))
            print("✓ Loaded XGBoost model")

            self.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
            print(f"✓ Loaded scaler: {type(self.scaler).__name__}")

            self.label_encoder = joblib.load(os.path.join(model_dir, 'label_encoder.pkl'))
            print(f"✓ Loaded label encoder ({len(self.label_encoder.classes_)} classes)")

            with open(os.path.join(model_dir, 'config.json'), 'r') as f:
                self.config = json.load(f)
            print("✓ Loaded configuration")

            print(f"\n🎯 Detection Mode: PROBABILITY THRESHOLD")
            print(f"   Malicious Threshold: {self.malicious_threshold*100:.0f}%")
            print(f"   (Any non-Benign probability > {self.malicious_threshold*100:.0f}% = ALERT)")

            self.stats = {
                'total_flows': 0,
                'benign': 0,
                'malicious': 0,
                'attack_types': defaultdict(int),
                'start_time': time.time()
            }
            self.stats_lock = threading.Lock()

            self.malicious_labels = [
                'SSH-Bruteforce', 'Bot',
                'DoS attacks-Hulk', 'DoS attacks-GoldenEye', 'DoS attacks-Slowloris',
                'DDOS attack-HOIC', 'DDOS attack-LOIC-UDP'
            ]

        except Exception as e:
            print(f"❌ Error loading models: {e}")
            sys.exit(1)

    def predict(self, features):
        """Predict using probability threshold"""
        try:
            feature_df = pd.DataFrame([features], columns=self.config['features'])
            feature_df = feature_df.replace([np.inf, -np.inf], 0)
            feature_df = feature_df.fillna(0)

            features_scaled = self.scaler.transform(feature_df)

            # Get probabilities for ALL classes
            proba = self.model.predict_proba(features_scaled)[0]

            # Find probability of Benign class
            benign_idx = list(self.label_encoder.classes_).index('Benign')
            benign_prob = proba[benign_idx]

            # Calculate total malicious probability (sum of all non-Benign)
            malicious_prob = 1.0 - benign_prob

            # Decision: If malicious probability > threshold, classify as malicious
            if malicious_prob >= self.malicious_threshold:
                # Find most likely malicious class
                malicious_probs = [(label, prob) for label, prob in zip(self.label_encoder.classes_, proba)
                                 if label != 'Benign']
                malicious_probs.sort(key=lambda x: x[1], reverse=True)

                attack_type = malicious_probs[0][0]
                label = 'Malicious'
                is_malicious = True
            else:
                attack_type = 'Benign'
                label = 'Benign'
                is_malicious = False

            # Update stats
            with self.stats_lock:
                self.stats['total_flows'] += 1
                if is_malicious:
                    self.stats['malicious'] += 1
                    self.stats['attack_types'][attack_type] += 1
                else:
                    self.stats['benign'] += 1

            # Create probability dict for all classes
            prob_dict = {label: prob * 100 for label, prob in zip(self.label_encoder.classes_, proba)}

            return label, is_malicious, benign_prob, malicious_prob, attack_type, prob_dict

        except Exception as e:
            print(f"⚠️  Prediction error: {e}")
            return "Unknown", False, 0, 0, "Unknown", {}

    def get_stats_summary(self):
        with self.stats_lock:
            runtime = time.time() - self.stats['start_time']

            return {
                'runtime': runtime,
                'total_flows': self.stats['total_flows'],
                'benign': self.stats['benign'],
                'malicious': self.stats['malicious'],
                'attack_types': dict(self.stats['attack_types']),
                'benign_pct': (self.stats['benign'] / self.stats['total_flows'] * 100) if self.stats['total_flows'] > 0 else 0,
                'malicious_pct': (self.stats['malicious'] / self.stats['total_flows'] * 100) if self.stats['total_flows'] > 0 else 0
            }

# =============================================================================
# REAL-TIME IDS
# =============================================================================
class RealtimeIDS:
    """Real-time IDS with threshold-based detection and evaluation logging"""

    def __init__(self, model_dir, interface='any', flow_timeout=120,
                 malicious_threshold=0.43, eval_logging=False, eval_dir="/opt/ids/evaluation"):
        self.flow_aggregator = FlowAggregator(flow_timeout=flow_timeout)
        self.feature_extractor = FeatureExtractor()
        self.inference_engine = ThresholdInferenceEngine(model_dir, malicious_threshold=malicious_threshold)
        self.interface = interface
        self.running = False

        self.last_flow_check = time.time()
        self.flow_check_interval = 2
        log_dir = '/opt/ids/logs'
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_file = os.path.join(log_dir, f'ids_alerts_{timestamp}.log')
        self.alert_logger = logging.getLogger('ids_alerts')
        self.alert_logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.alert_logger.addHandler(file_handler)

        print(f"📝 Alert logging to: {log_file}")
        self.prediction_logger = PredictionLogger(output_dir=eval_dir, enabled=eval_logging)
        self.latest_confidence = {}
        self.confidence_lock = threading.Lock()

    def packet_callback(self, packet):
        try:
            self.flow_aggregator.add_packet(packet)

            current_time = time.time()
            if current_time - self.last_flow_check > self.flow_check_interval:
                self.process_expired_flows()
                self.last_flow_check = current_time
        except:
            pass

    def process_expired_flows(self):
        expired_flows = self.flow_aggregator.get_expired_flows()

        for flow_key, flow in expired_flows:
            features = self.feature_extractor.extract_features(flow)

            if features is not None:
                label, is_malicious, benign_prob, malicious_prob, attack_type, prob_dict = self.inference_engine.predict(features)
                self.prediction_logger.log_prediction(
                    flow_key=flow_key,
                    flow=flow,
                    predicted_label=label,
                    attack_type=attack_type,
                    benign_prob=benign_prob,
                    malicious_prob=malicious_prob
                )
                with self.confidence_lock:
                    self.latest_confidence = prob_dict

                if is_malicious:
                    prob_str = ", ".join([f"{cls}: {prob:.1f}%" for cls, prob in sorted(prob_dict.items(), key=lambda x: x[1], reverse=True)])
                    alert_msg = (f"{attack_type} detected from {flow['src_ip']}:{flow['src_port']} → "
                                 f"{flow['dst_ip']}:{flow['dst_port']} | {prob_str}")
                    self.alert_logger.info(alert_msg)

    def display_dashboard(self):
        while self.running:
            time.sleep(1)
            stats = self.inference_engine.get_stats_summary()
            os.system('clear' if os.name != 'nt' else 'cls')
            print(f"\n{'='*60}")
            print("IDS INFERENCE SYSTEM")
            if self.prediction_logger.enabled:
                print("📊 EVALUATION MODE - Logging predictions to CSV")
            print(f"{'='*60}\n")

            runtime_min = int(stats['runtime'] // 60)
            runtime_sec = int(stats['runtime'] % 60)
            print(f"Runtime: {runtime_min}m {runtime_sec}s | Time: {datetime.now().strftime('%H:%M:%S')}")

            print("\nTRAFFIC SUMMARY:")
            print(f"  Total Processed: {stats['total_flows']:,}")
            print(f"  Benign:          {stats['benign']:,} ({stats['benign_pct']:.1f}%)")
            print(f"  Malicious:       {stats['malicious']:,} ({stats['malicious_pct']:.1f}%)")
            if self.prediction_logger.enabled:
                print(f"\n  Predictions Logged: {self.prediction_logger.prediction_count:,}")

            if stats['malicious'] > 500000 and stats['attack_types']:
                print(f"\nATTACK BREAKDOWN:")
                for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
                    pct = (count / stats['malicious'] * 100)
                    print(f"  {attack_type:25s}: {count:5,} ({pct:.1f}%)")

            print(f"\n{'='*60}")
            print("Press Ctrl+C to stop")
            print(f"{'='*60}\n")

    def start(self):
        self.running = True

        print(f"\n{'='*60}")
        print("🚀 STARTING REAL-TIME IDS")
        print(f"{'='*60}\n")
        print(f"Interface: {self.interface}")
        print(f"Flow Timeout: {self.flow_aggregator.flow_timeout}s")
        if self.prediction_logger.enabled:
            print(f"Evaluation Mode: ENABLED")
            print(f"Predictions CSV: {self.prediction_logger.csv_path}")
        print(f"\nCapturing traffic... Press Ctrl+C to stop\n")

        dashboard_thread = threading.Thread(target=self.display_dashboard, daemon=True)
        dashboard_thread.start()
        try:
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                filter="ip",
                quiet=True
            )
        except KeyboardInterrupt:
            print("\n\n⏹️  Stopping IDS...")
            self.stop()

    def stop(self):
        self.running = False

        all_flows = self.flow_aggregator.get_all_flows()
        print(f"\nProcessing {len(all_flows)} remaining flows...")
        for flow_key, flow in all_flows:
            features = self.feature_extractor.extract_features(flow)
            if features is not None:
                label, is_malicious, benign_prob, malicious_prob, attack_type, prob_dict = self.inference_engine.predict(features)
                self.prediction_logger.log_prediction(
                    flow_key=flow_key,
                    flow=flow,
                    predicted_label=label,
                    attack_type=attack_type,
                    benign_prob=benign_prob,
                    malicious_prob=malicious_prob
                )
        self.prediction_logger.finalize()
        stats = self.inference_engine.get_stats_summary()
        print(f"\n{'='*60}")
        print("FINAL STATISTICS")
        print(f"{'='*60}\n")
        print(f"Total Flows: {stats['total_flows']:,}")
        print(f"Benign: {stats['benign']:,} ({stats['benign_pct']:.1f}%)")
        print(f"Malicious: {stats['malicious']:,} ({stats['malicious_pct']:.1f}%)")

        if stats['attack_types']:
            print(f"\nAttack Types Detected:")
            for attack, count in stats['attack_types'].items():
                print(f"  • {attack}: {count}")

        print(f"\n✅ IDS stopped successfully\n")

# =============================================================================
# MAIN
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Real-time IDS with threshold-based detection')
    parser.add_argument('--model-dir', required=True, help='Directory containing trained models')
    parser.add_argument('--interface', default='enX0', help='Network interface to monitor')
    parser.add_argument('--flow-timeout', type=int, default=3, help='Flow timeout in seconds')
    parser.add_argument('--threshold', type=float, default=0.63,
                       help='Malicious probability threshold (0.0-1.0, default: 0.3)')
    parser.add_argument('--eval', action='store_true', help='Enable evaluation mode (log predictions to CSV)')
    parser.add_argument('--eval-dir', default='/opt/ids/evaluation', help='Directory for evaluation CSV output')
    args = parser.parse_args()
    if not os.path.exists(args.model_dir):
        print(f"❌ Model directory not found: {args.model_dir}")
        sys.exit(1)
    if not 0 <= args.threshold <= 1:
        print(f"❌ Threshold must be between 0.0 and 1.0")
        sys.exit(1)
    ids = RealtimeIDS(
        model_dir=args.model_dir,
        interface=args.interface,
        flow_timeout=args.flow_timeout,
        malicious_threshold=args.threshold,
        eval_logging=args.eval,
        eval_dir=args.eval_dir
    )
    ids.start()

if __name__ == '__main__':
    main()