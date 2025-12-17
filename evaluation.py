#!/usr/bin/env python3
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import os
import glob

LABELS = ['Benign', 'Malicious']

def parse_timestamp(ts_str):
    """Parse ISO format timestamp"""
    try:
        return pd.to_datetime(ts_str)
    except:
        return None

def normalize_timestamp(ts):
    """Remove timezone info for comparison"""
    if pd.isna(ts):
        return ts
    if ts.tzinfo is not None:
        return pd.Timestamp(ts.to_pydatetime().replace(tzinfo=None))
    return ts

def load_ground_truth(filepath):
    """Load enhanced ground truth CSV with source IP"""
    df = pd.read_csv(filepath)

    # Parse timestamps
    df['phase_start'] = pd.to_datetime(df['phase_start'], format='ISO8601').apply(normalize_timestamp)
    df['phase_end'] = pd.to_datetime(df['phase_end'], format='ISO8601').apply(normalize_timestamp)
    # Add source file identifier
    df['source_file'] = os.path.basename(filepath)
    # Ensure source_ip column exists
    if 'source_ip' not in df.columns:
        print(f"  ⚠️  Warning: {filepath} missing source_ip column. Using fallback matching.")
        df['source_ip'] = None
    return df

def load_multiple_ground_truths(filepaths):
    """Load and merge multiple ground truth CSVs from multiple attackers"""
    all_dfs = []
    print(f"\n  Loading {len(filepaths)} ground truth file(s):")

    for filepath in filepaths:
        if not os.path.exists(filepath):
            print(f"    ⚠️  File not found: {filepath}")
            continue
        df = load_ground_truth(filepath)
        all_dfs.append(df)
        # Show summary for each file
        benign_count = len(df[df['label'] == 'Benign'])
        malicious_count = len(df[df['label'] == 'Malicious'])
        source_ips = df['source_ip'].unique() if 'source_ip' in df.columns else ['Unknown']
        print(f"    • {os.path.basename(filepath)}: {len(df)} phases ({benign_count} benign, {malicious_count} malicious)")

    if not all_dfs:
        raise ValueError("No valid ground truth files found!")
    combined_df = pd.concat(all_dfs, ignore_index=True)
    combined_df = combined_df.sort_values('phase_start').reset_index(drop=True)
    print(f"\n  Combined: {len(combined_df)} total phases")
    return combined_df

def load_predictions(filepath):
    df = pd.read_csv(filepath)
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='ISO8601').apply(normalize_timestamp)
    if 'src_ip' not in df.columns:
        print(f"  ⚠️  Warning: Predictions missing src_ip column. IP-based matching disabled.")
        df['src_ip'] = None
    print(f"  Loaded {len(df)} predictions from {os.path.basename(filepath)}")
    return df

def assign_ground_truth_labels_enhanced(predictions_df, ground_truth_df, time_buffer_seconds=5, use_ip_matching=True):
    labeled_predictions = []

    # Check if IP matching is possible
    has_prediction_ips = predictions_df['src_ip'].notna().any()
    has_ground_truth_ips = ground_truth_df['source_ip'].notna().any()
    ip_matching_enabled = use_ip_matching and has_prediction_ips and has_ground_truth_ips

    if use_ip_matching and not ip_matching_enabled:
        print("\n  ⚠️  IP matching requested but not possible (missing source IPs)")
        print("      Falling back to time-only matching")
    for _, pred in predictions_df.iterrows():
        pred_time = pred['timestamp']
        pred_src_ip = pred.get('src_ip')
        matching_phases = []
        # Step 1: Find all phases matching by time window
        for _, gt in ground_truth_df.iterrows():
            start = gt['phase_start'] - timedelta(seconds=time_buffer_seconds)
            end = gt['phase_end'] + timedelta(seconds=time_buffer_seconds)
            if start <= pred_time <= end:
                # Step 2: Apply IP filtering if enabled
                if ip_matching_enabled:
                    gt_src_ip = gt.get('source_ip')
                    # Only match if IPs are equal
                    if pd.notna(pred_src_ip) and pd.notna(gt_src_ip):
                        if str(pred_src_ip).strip() == str(gt_src_ip).strip():
                            matching_phases.append({
                                'label': gt['label'],
                                'traffic_type': gt['traffic_type'],
                                'source': gt['source_file'],
                                'source_ip': gt_src_ip,
                                'attacker_id': gt.get('attacker_id', 'unknown')
                            })
                else:
                    # Time-only matching (fallback)
                    matching_phases.append({
                        'label': gt['label'],
                        'traffic_type': gt['traffic_type'],
                        'source': gt['source_file'],
                        'source_ip': gt.get('source_ip'),
                        'attacker_id': gt.get('attacker_id', 'unknown')
                    })

        # Step 3: Determine final label from matches
        if not matching_phases:
            # No matching phase - outside test windows
            assigned_label = None
            traffic_type = None
            sources = None
            source_ips = None
            attacker_ids = None
        else:
            # Check if ANY matching phase is Malicious
            malicious_phases = [p for p in matching_phases if p['label'] == 'Malicious']

            if malicious_phases:
                # At least one attack phase - label as Malicious
                assigned_label = 'Malicious'
                traffic_type = malicious_phases[0]['traffic_type']
            else:
                # All matching phases are Benign
                assigned_label = 'Benign'
                traffic_type = matching_phases[0]['traffic_type']
            sources = ', '.join(set(p['source'] for p in matching_phases))
            source_ips = ', '.join(set(str(p.get('source_ip', 'unknown')) for p in matching_phases))
            attacker_ids = ', '.join(set(p.get('attacker_id', 'unknown') for p in matching_phases))

        labeled_predictions.append({
            'timestamp': pred_time,
            'predicted_label': pred['predicted_label'],
            'actual_label': assigned_label,
            'traffic_type': traffic_type,
            'sources': sources,
            'source_ips': source_ips,
            'attacker_ids': attacker_ids,
            'flow_id': pred.get('flow_id', None),
            'pred_src_ip': pred.get('src_ip', None),
            'dst_ip': pred.get('dst_ip', None),
            'num_matches': len(matching_phases)
        })
    return pd.DataFrame(labeled_predictions)

def compute_binary_metrics(y_true, y_pred):
    """Compute binary classification metrics"""
    y_true_binary = np.array([0 if y == 'Benign' else 1 for y in y_true])
    y_pred_binary = np.array([0 if y == 'Benign' else 1 for y in y_pred])
    # Confusion matrix
    tp = np.sum((y_true_binary == 1) & (y_pred_binary == 1))
    tn = np.sum((y_true_binary == 0) & (y_pred_binary == 0))
    fp = np.sum((y_true_binary == 0) & (y_pred_binary == 1))
    fn = np.sum((y_true_binary == 1) & (y_pred_binary == 0))
    total = tp + tn + fp + fn
    # Performance Metrics
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    return {
        'confusion_matrix': {
            'TP': int(tp), 'TN': int(tn),
            'FP': int(fp), 'FN': int(fn)
        },
        'metrics': {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'specificity': float(specificity),
            'f1_score': float(f1),
            'false_positive_rate': float(fpr)
        },
        'counts': {
            'total': int(total),
            'actual_benign': int(np.sum(y_true_binary == 0)),
            'actual_malicious': int(np.sum(y_true_binary == 1)),
            'predicted_benign': int(np.sum(y_pred_binary == 0)),
            'predicted_malicious': int(np.sum(y_pred_binary == 1))
        }
    }

def print_results(results, labeled_df, ground_truth_df, num_sources):
    cm = results['confusion_matrix']
    metrics = results['metrics']
    counts = results['counts']
    # Calculate derived rates for interpretation
    fpr = metrics['false_positive_rate']
    fnr = 1 - metrics['recall']
    print(f"\n{'='*70}")
    print("  IDS MODEL EVALUATION RESULTS")
    print("  Binary Classification: Benign vs Malicious")
    if num_sources > 1:
        print(f"  Attack Sources: {num_sources}")
    print(f"{'='*70}")
    # Confusion Matrix with Box Drawing
    print("\n┌─────────────────────────────────────────────────────────────────────┐")
    print("│                      CONFUSION MATRIX                               │")
    print("├─────────────────────────────────────────────────────────────────────┤")
    print("│                                                                     │")
    print("│                              Predicted                              │")
    print("│                      Benign          Malicious                      │")
    print("│              ┌────────────────┬────────────────┐                    │")
    print("│    Actual    │                │                │                    │")
    print(f"│    Benign    │  TN = {cm['TN']:<6} │  FP = {cm['FP']:<6} │  = {counts['actual_benign']:<8} │")
    print("│              ├────────────────┼────────────────┤                    │")
    print(f"│    Malicious │  FN = {cm['FN']:<6} │  TP = {cm['TP']:<6} │  = {counts['actual_malicious']:<8} │")
    print("│              └────────────────┴────────────────┘                    │")
    print(f"│                    = {counts['predicted_benign']:<8}     = {counts['predicted_malicious']:<8}                │")
    print("│                                                                     │")
    print("└─────────────────────────────────────────────────────────────────────┘")
    # Performance Metrics with Box Drawing
    print("\n┌─────────────────────────────────────────────────────────────────────┐")
    print("│                      PERFORMANCE METRICS                            │")
    print("├─────────────────────────────────────────────────────────────────────┤")
    print(f"│  Accuracy:              {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:6.2f}%)                    │")
    print(f"│  Precision:             {metrics['precision']:.4f}  ({metrics['precision']*100:6.2f}%)                    │")
    print(f"│  Recall (Detection):    {metrics['recall']:.4f}  ({metrics['recall']*100:6.2f}%)                    │")
    print(f"│  Specificity:           {metrics['specificity']:.4f}  ({metrics['specificity']*100:6.2f}%)                    │")
    print(f"│  F1 Score:              {metrics['f1_score']:.4f}  ({metrics['f1_score']*100:6.2f}%)                    │")
    print("├─────────────────────────────────────────────────────────────────────┤")
    print(f"│  False Positive Rate:   {fpr:.4f}  ({fpr*100:6.2f}%)                    │")
    print(f"│  False Negative Rate:   {fnr:.4f}  ({fnr*100:6.2f}%)                    │")
    print("└─────────────────────────────────────────────────────────────────────┘")
    # Interpretation
    print("\n📊 Interpretation:")
    print(f"  • True Positives (TP):  {cm['TP']:,} attacks correctly detected")
    print(f"  • True Negatives (TN):  {cm['TN']:,} benign flows correctly classified")
    print(f"  • False Positives (FP): {cm['FP']:,} benign flows incorrectly flagged as attacks")
    print(f"  • False Negatives (FN): {cm['FN']:,} attacks missed by the model")
    # Detection by traffic type
    valid_df = labeled_df.dropna(subset=['actual_label', 'traffic_type'])
    if len(valid_df) > 0:
        print("\n📈 Detection by Traffic Type:")

        for traffic_type in sorted(valid_df['traffic_type'].unique()):
            subset = valid_df[valid_df['traffic_type'] == traffic_type]
            total = len(subset)
            correct = sum(subset['predicted_label'] == subset['actual_label'])
            accuracy = correct / total if total > 0 else 0

            if subset['actual_label'].iloc[0] == 'Malicious':
                detected = sum(subset['predicted_label'] == 'Malicious')
                print(f"  • {traffic_type:20s}: {detected:>6}/{total:<6} detected ({accuracy*100:.1f}%)")
            else:
                correct_benign = sum(subset['predicted_label'] == 'Benign')
                print(f"  • {traffic_type:20s}: {correct_benign:>6}/{total:<6} correct ({accuracy*100:.1f}%)")
    # Per-source breakdown
    if num_sources > 1 and 'source_file' in ground_truth_df.columns:
        print("\n📡 Per-Source Summary:")
        for source in ground_truth_df['source_file'].unique():
            source_phases = ground_truth_df[ground_truth_df['source_file'] == source]
            benign = len(source_phases[source_phases['label'] == 'Benign'])
            malicious = len(source_phases[source_phases['label'] == 'Malicious'])
            attack_types = source_phases[source_phases['label'] == 'Malicious']['traffic_type'].unique()
            attack_str = ', '.join(attack_types) if len(attack_types) > 0 else 'None'
            print(f"  • {source}:")
            print(f"      Phases: {len(source_phases)} ({benign} benign, {malicious} malicious)")
            print(f"      Attacks: {attack_str}")
    # Per-source accuracy (if IP matching was used)
    if num_sources > 1 and 'source_ips' in labeled_df.columns:
        unique_source_ips = labeled_df['source_ips'].dropna().unique()
        if len(unique_source_ips) > 0:
            print("\n📊 Per-Source Accuracy (IP-Matched):")

            for source in ground_truth_df['source_file'].unique():
                # Filter predictions that matched this source
                source_preds = labeled_df[labeled_df['sources'].notna() & labeled_df['sources'].str.contains(source, na=False)]
                if len(source_preds) > 0:
                    valid_source = source_preds.dropna(subset=['actual_label'])
                    if len(valid_source) > 0:
                        y_true_source = valid_source['actual_label'].tolist()
                        y_pred_source = valid_source['predicted_label'].tolist()
                        source_metrics = compute_binary_metrics(y_true_source, y_pred_source)
                        print(f"  • {source}:")
                        print(f"      Matched predictions: {len(valid_source):,}")
                        print(f"      Accuracy:  {source_metrics['metrics']['accuracy']*100:>5.1f}% | Precision: {source_metrics['metrics']['precision']*100:>5.1f}% | Recall: {source_metrics['metrics']['recall']*100:>5.1f}%")

    # IP matching statistics
    if 'source_ips' in labeled_df.columns:
        unique_source_ips = labeled_df['source_ips'].dropna().unique()
        if len(unique_source_ips) > 0 and len(unique_source_ips) <= 10:
            print("\n🌐 Source IP Statistics:")
            print(f"  Unique source IPs detected: {len(unique_source_ips)}")
            for ip in sorted(unique_source_ips):
                ip_preds = labeled_df[labeled_df['source_ips'] == ip]
                valid_ip = ip_preds.dropna(subset=['actual_label'])
                benign = sum(valid_ip['actual_label'] == 'Benign')
                malicious = sum(valid_ip['actual_label'] == 'Malicious')
                print(f"    {ip:15s}: {len(valid_ip):>6,} flows ({benign:,} benign, {malicious:,} malicious)")

def generate_report(labeled_df, ground_truth_df, output_dir, session_id, num_sources):
    valid_df = labeled_df.dropna(subset=['actual_label'])
    if len(valid_df) == 0:
        print(f"\n❌ ERROR: No predictions matched to ground truth phases!")
        print("   Possible causes:")
        print("   • Time synchronization issues between attacker(s) and victim")
        print("   • IP mismatch (check source IPs in ground truth vs predictions)")
        print("   • Timestamps don't overlap - check time ranges")
        print("   • Try: --time-buffer 30 or --no-ip-matching")
        return None
    y_true = valid_df['actual_label'].tolist()
    y_pred = valid_df['predicted_label'].tolist()
    if 'num_matches' in labeled_df.columns:
        multi_match = labeled_df[labeled_df['num_matches'] > 1]
        if len(multi_match) > 0:
            print(f"  Multiple phase matches:   {len(multi_match):,} (concurrent traffic detected)")
    results = compute_binary_metrics(y_true, y_pred)
    print_results(results, valid_df, ground_truth_df, num_sources)
    os.makedirs(output_dir, exist_ok=True)
    output_csv = f"{output_dir}/{session_id}_labeled_predictions.csv"
    labeled_df.to_csv(output_csv, index=False)
    output_json = f"{output_dir}/{session_id}_results.json"
    source_files = ground_truth_df['source_file'].unique().tolist() if 'source_file' in ground_truth_df.columns else []
    all_results = {
        'session_id': session_id,
        'timestamp': datetime.now().isoformat(),
        'num_attack_sources': num_sources,
        'source_files': source_files,
        'data_summary': {
            'total_predictions': len(labeled_df),
            'matched_predictions': len(valid_df),
            'unmatched_predictions': len(labeled_df) - len(valid_df),
            'total_ground_truth_phases': len(ground_truth_df)
        },
        'confusion_matrix': results['confusion_matrix'],
        'metrics': results['metrics'],
        'counts': results['counts']
    }
    with open(output_json, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n📁 Results saved to:")
    print(f"  • {output_csv}")
    print(f"  • {output_json}")
    return all_results

def expand_glob_patterns(patterns):
    """Expand glob patterns in file paths"""
    expanded = []
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            expanded.extend(matches)
        else:
            expanded.append(pattern)
    return list(set(expanded))

def main():
    parser = argparse.ArgumentParser(
        description='ENHANCED IDS Evaluation with Source IP Matching',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Multi-source with IP matching (recommended)
  %(prog)s -g attacker1.csv attacker2.csv -p predictions.csv

  # Using glob pattern
  %(prog)s -g "eval_*_ground_truth.csv" -p predictions.csv

  # Disable IP matching (time-only)
  %(prog)s -g attacker1.csv attacker2.csv -p predictions.csv --no-ip-matching

  # Increase time buffer for clock skew
  %(prog)s -g attacker1.csv -p predictions.csv --time-buffer 30
        """
    )
    parser.add_argument('--ground-truth', '-g', required=True, nargs='+',
                        help='Path(s) to ground truth CSV file(s) from attacker(s)')
    parser.add_argument('--predictions', '-p', required=True,
                        help='Path to predictions CSV from victim/inference')
    parser.add_argument('--output-dir', '-o', default='./evaluation_results',
                        help='Output directory for results (default: ./evaluation_results)')
    parser.add_argument('--time-buffer', '-t', type=int, default=5,
                        help='Time buffer in seconds for matching (default: 5)')
    parser.add_argument('--no-ip-matching', action='store_true',
                        help='Disable source IP matching (use time-only matching)')
    parser.add_argument('--session-id', '-s', default=None,
                        help='Session ID for output files (default: auto-generated)')

    args = parser.parse_args()
    ground_truth_files = expand_glob_patterns(args.ground_truth)
    num_sources = len(ground_truth_files)
    session_id = args.session_id or f"eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print("="*70)
    print("  IDS MODEL EVALUATION")
    print("  Binary Classification: Benign vs Malicious")
    if num_sources > 1:
        print(f"  Multi-Source Mode: {num_sources} attack sources")
    print("="*70)
    print(f"\nSession ID: {session_id}")
    print(f"Ground Truth Files: {num_sources}")
    for f in ground_truth_files:
        print(f"  • {f}")
    print(f"Predictions: {args.predictions}")
    print(f"Time Buffer: {args.time_buffer}s")
    ip_matching_status = 'DISABLED (time-only)' if args.no_ip_matching else 'ENABLED'
    if not args.no_ip_matching:
        print(f"IP Matching: {ip_matching_status}")
    if not os.path.exists(args.predictions):
        print(f"\n❌ Predictions file not found: {args.predictions}")
        return
    print("\n📂 Loading data...")
    try:
        ground_truth_df = load_multiple_ground_truths(ground_truth_files)
    except ValueError as e:
        print(f"\n❌ Error: {e}")
        return
    predictions_df = load_predictions(args.predictions)
    print(f"\n  Ground truth time range (combined):")
    print(f"    Start: {ground_truth_df['phase_start'].min()}")
    print(f"    End:   {ground_truth_df['phase_end'].max()}")
    print(f"\n  Predictions time range:")
    print(f"    Start: {predictions_df['timestamp'].min()}")
    print(f"    End:   {predictions_df['timestamp'].max()}")
    print("\n🔄 Matching predictions to ground truth phases...")
    labeled_df = assign_ground_truth_labels_enhanced(
        predictions_df,
        ground_truth_df,
        args.time_buffer,
        use_ip_matching=not args.no_ip_matching
    )
    matched = labeled_df['actual_label'].notna().sum()
    print(f"\n  Matched: {matched:,} / {len(labeled_df):,} predictions")
    print(f"\n📈 Data Summary")
    print(f"  Total predictions logged: {len(labeled_df):,}")
    print(f"  Matched to ground truth:  {matched:,}")
    print(f"  Unmatched (outside test): {len(labeled_df) - matched:,}")
    generate_report(labeled_df, ground_truth_df, args.output_dir, session_id, num_sources)
    print(f"\n{'='*70}")
    print("  EVALUATION COMPLETE")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()