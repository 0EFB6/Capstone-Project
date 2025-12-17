#!/bin/bash
################################################################################
# IDS EVALUATION TRAFFIC SIMULATOR
# Purpose: Generate labeled traffic (benign + attacks) for ML model evaluation
# Output: Ground truth CSV with BINARY labels (Benign/Malicious)
################################################################################

TARGET_IP="${TARGET_IP:-10.0.0.13}"
EVALUATION_ID="eval_$(date +%Y%m%d_%H%M%S)"
GROUND_TRUTH_CSV="${EVALUATION_ID}_ground_truth.csv"
TRAFFIC_LOG="${EVALUATION_ID}_traffic.log"

# Duration settings (in seconds)
PHASE_DURATION=${PHASE_DURATION:-60}  
COOLDOWN_DURATION=${COOLDOWN_DURATION:-30}

################################################################################
# LOGGING FUNCTIONS
################################################################################

init_ground_truth_csv() {
    echo "timestamp,phase_start,phase_end,traffic_type,label,packet_count,session_id" > "$GROUND_TRUTH_CSV"
    echo "Evaluation ID: $EVALUATION_ID" > "$TRAFFIC_LOG"
    echo "Target: $TARGET_IP" >> "$TRAFFIC_LOG"
    echo "Started: $(date -Iseconds)" >> "$TRAFFIC_LOG"
    echo "Phase Duration: ${PHASE_DURATION}s" >> "$TRAFFIC_LOG"
    echo "Labels: Binary (Benign / Malicious)" >> "$TRAFFIC_LOG"
    echo "----------------------------------------" >> "$TRAFFIC_LOG"
}

# Log a traffic phase to ground truth CSV
# Usage: log_ground_truth "traffic_type" "label" "packet_count" "phase_start" "phase_end"
log_ground_truth() {
    local traffic_type="$1"
    local label="$2"
    local packet_count="$3"
    local phase_start="$4"
    local phase_end="$5"
    local timestamp=$(date -Iseconds)

    echo "${timestamp},${phase_start},${phase_end},${traffic_type},${label},${packet_count},${EVALUATION_ID}" >> "$GROUND_TRUTH_CSV"
    echo "[$(date '+%H:%M:%S')] Logged: $label ($traffic_type, $packet_count packets)" >> "$TRAFFIC_LOG"
}

log_message() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$TRAFFIC_LOG"
}

################################################################################
# BENIGN TRAFFIC GENERATORS
################################################################################
generate_benign_http() {
    local duration=$1
    local start_time=$(date -Iseconds)
    local count=0
    local end_time=$((SECONDS + duration))
    local batch_size=100

    log_message "Starting: Benign HTTP Browsing (${duration}s)"

    while [ $SECONDS -lt $end_time ]; do
        curl -s -m 5 \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            -H "Accept-Language: en-US,en;q=0.5" \
            http://$TARGET_IP/ > /dev/null 2>&1

        count=$((count + 1))
        if [ $((count % 1000)) -eq 0 ]; then
            log_message "  Progress: $count requests sent"
        fi
        if [ $((count % batch_size)) -eq 0 ]; then
            sleep 0.1
        fi
    done

    local end_timestamp=$(date -Iseconds)
    log_ground_truth "http_browsing" "Benign" "$count" "$start_time" "$end_timestamp"
    log_message "Completed: Benign HTTP - $count requests"
}

# Normal ICMP ping (Benign)
generate_benign_icmp() {
    local duration=$1
    local start_time=$(date -Iseconds)
    local count=$((duration * 2))

    log_message "Starting: Benign ICMP Ping (${duration}s)"

    timeout ${duration}s ping -i 0.5 $TARGET_IP > /dev/null 2>&1

    local end_timestamp=$(date -Iseconds)
    log_ground_truth "icmp_ping" "Benign" "$count" "$start_time" "$end_timestamp"
    log_message "Completed: Benign ICMP - ~$count pings"
}

generate_benign_icmp_2() {
    local duration=$1
    local start_time=$(date -Iseconds)
    local count=$((duration * 2))

    log_message "Starting: Benign ICMP Ping (${duration}s)"

    timeout ${duration}s ping -c 5000 -i 0.01 $TARGET_IP > /dev/null 2>&1

    local end_timestamp=$(date -Iseconds)
    log_ground_truth "icmp_ping" "Benign" "$count" "$start_time" "$end_timestamp"
    log_message "Completed: Benign ICMP - ~$count pings"
}

# Mixed benign traffic
generate_benign_mixed() {
    local duration=$1
    local segment=$((duration / 3))

    log_message "Starting: Mixed Benign Traffic (${duration}s)"
    generate_benign_http $segment
    generate_benign_icmp $segment
    generate_benign_icmp_2 $segment
}

################################################################################
# ATTACK TRAFFIC GENERATORS (All labeled as "Malicious")
################################################################################
generate_slowloris() {
    local duration=$1
    local start_time=$(date -Iseconds)
    local count=0

    log_message "Starting: Slowloris Attack (${duration}s) [MALICIOUS]"

    if command -v slowloris &> /dev/null; then
        timeout ${duration}s slowloris -s 200 $TARGET_IP 2>/dev/null &
        local pid=$!
        sleep $duration
        kill $pid 2>/dev/null
        count=$((duration * 200))
    else
        log_message "Slowloris Attack Error!"
    fi

    local end_timestamp=$(date -Iseconds)
    log_ground_truth "slowloris" "Malicious" "$count" "$start_time" "$end_timestamp"
    log_message "Completed: Slowloris Attack - ~$count connections"
}

generate_hoic() {
    local duration=$1
    local start_time=$(date -Iseconds)
    local count=0
    local end_time=$((SECONDS + duration))

    log_message "Starting: HOIC-style HTTP Flood (${duration}s) [MALICIOUS]"
    while [ $SECONDS -lt $end_time ]; do
        for i in {1..100}; do
            curl -s -m 1 http://$TARGET_IP/ > /dev/null 2>&1 &
            count=$((count + 1))
        done
        sleep 0.1
    done
    wait 2>/dev/null

    local end_timestamp=$(date -Iseconds)
    log_ground_truth "http_flood_hoic" "Malicious" "$count" "$start_time" "$end_timestamp"
    log_message "Completed: HOIC Flood - $count requests"
}

generate_syn_flood() {
    local duration=$1
    local start_time=$(date -Iseconds)

    log_message "Starting: SYN Flood (${duration}s) [MALICIOUS]"

    if command -v hping3 &> /dev/null; then
        timeout ${duration}s sudo hping3 -S --flood -p 80 $TARGET_IP > /dev/null 2>&1 &
        local pid=$!
        sleep $duration
        kill $pid 2>/dev/null
        local count=$((duration * 10000))
    else
        log_message "WARNING: hping3 not installed, skipping SYN flood"
        local count=0
    fi

    local end_timestamp=$(date -Iseconds)
    log_ground_truth "syn_flood" "Malicious" "$count" "$start_time" "$end_timestamp"
    log_message "Completed: SYN Flood - ~$count packets"
}

################################################################################
# EVALUATION SCENARIOS
################################################################################
cooldown() {
    log_message "Cooldown: ${COOLDOWN_DURATION}s pause..."
    sleep $COOLDOWN_DURATION
}

run_quick_test() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  🧪 QUICK EVALUATION TEST (~5 minutes)"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  Labels: Benign / Malicious (Binary)"
    echo ""

    local phase=60

    init_ground_truth_csv
    generate_benign_http $phase
    generate_slowloris $phase
    generate_hoic $phase
    generate_syn_flood $phase
    generate_benign_icmp $phase
    generate_benign_icmp_2 $phase
    finalize_evaluation
}

run_standard_test() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  🧪 STANDARD EVALUATION TEST (~30 minutes)"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  Labels: Benign / Malicious (Binary)"
    echo ""

    local phase=180
    init_ground_truth_csv
    generate_benign_mixed $phase
    cooldown
    generate_slowloris $phase
    cooldown
    generate_benign_http $phase
    cooldown
    generate_hoic $phase
    cooldown
    generate_benign_mixed $phase
    cooldown
    generate_benign_http $phase

    finalize_evaluation
}

run_full_test() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  🧪 FULL EVALUATION TEST (~2 hour)"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  Labels: Benign / Malicious (Binary)"
    echo ""

    local phase=900 
    local attack_phase=420

    init_ground_truth_csv
    generate_benign_mixed $phase
    cooldown
    generate_hoic $attack_phase
    cooldown
    generate_benign_http $phase
    cooldown
    generate_benign_icmp $phase
    cooldown
    generate_syn_flood $attack_phase
    cooldown
    generate_benign_icmp_2 $phase
    cooldown
    generate_hoic $attack_phase
    cooldown
    generate_benign_mixed $phase
    cooldown
    generate_slowloris $attack_phase
    cooldown
    generate_syn_flood $attack_phase
    cooldown
    generate_benign_http $phase
    cooldown
    generate_benign_icmp_2 $phase
    cooldown
    generate_benign_http $phase
    cooldown
    finalize_evaluation
}

run_custom_test() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  🧪 CUSTOM EVALUATION TEST"
    echo "════════════════════════════════════════════════════════════════════════════"

    read -p "Phase duration (seconds, default 60): " phase
    phase=${phase:-60}

    echo ""
    echo "Available traffic types:"
    echo "  1) Benign HTTP"
    echo "  2) Benign ICMP"
    echo "  3) Benign Mixed"
    echo "  4) Slowloris [MALICIOUS]"
    echo "  5) HOIC [MALICIOUS]"
    echo "  6) Hulk [MALICIOUS]"
    echo "  7) GoldenEye [MALICIOUS]"
    echo "  8) SYN Flood [MALICIOUS]"
    echo ""
    read -p "Enter sequence (comma-separated, e.g., 1,5,1,6,1): " sequence

    init_ground_truth_csv

    IFS=',' read -ra types <<< "$sequence"
    for type in "${types[@]}"; do
        case $type in
            1) generate_benign_http $phase ;;
            2) generate_benign_icmp $phase ;;
            3) generate_benign_mixed $phase ;;
            4) generate_slowloris $phase ;;
            5) generate_hoic $phase ;;
            6) generate_syn_flood $phase ;;
            *) log_message "Unknown type: $type, skipping" ;;
        esac
        cooldown
    done

    finalize_evaluation
}

run_single_type() {
    local type=$1
    local duration=${2:-60}

    init_ground_truth_csv

    case $type in
        benign-http) generate_benign_http $duration ;;
        benign-icmp) generate_benign_icmp $duration ;;
        benign-mixed) generate_benign_mixed $duration ;;
        slowloris) generate_slowloris $duration ;;
        hoic) generate_hoic $duration ;;
        syn-flood) generate_syn_flood $duration ;;
        *) echo "Unknown type: $type"; exit 1 ;;
    esac

    finalize_evaluation
}

################################################################################
# FINALIZATION
################################################################################

finalize_evaluation() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  📊 EVALUATION COMPLETE"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Evaluation ID: $EVALUATION_ID"
    echo "Ground Truth CSV: $GROUND_TRUTH_CSV"
    echo "Traffic Log: $TRAFFIC_LOG"
    echo ""
    echo "Ground Truth Summary (Binary Labels):"
    echo "----------------------------------------"

    # Count by label
    echo "Label Counts:"
    local benign_phases=$(tail -n +2 "$GROUND_TRUTH_CSV" | grep ",Benign," | wc -l)
    local malicious_phases=$(tail -n +2 "$GROUND_TRUTH_CSV" | grep ",Malicious," | wc -l)
    printf "  %-15s %s phases\n" "Benign:" "$benign_phases"
    printf "  %-15s %s phases\n" "Malicious:" "$malicious_phases"

    echo ""
    echo "Total Packets by Label:"
    local benign_packets=$(tail -n +2 "$GROUND_TRUTH_CSV" | grep ",Benign," | awk -F',' '{sum+=$6} END {print sum+0}')
    local malicious_packets=$(tail -n +2 "$GROUND_TRUTH_CSV" | grep ",Malicious," | awk -F',' '{sum+=$6} END {print sum+0}')
    printf "  %-15s %d packets\n" "Benign:" "$benign_packets"
    printf "  %-15s %d packets\n" "Malicious:" "$malicious_packets"

    echo ""
    echo "Attack Types Simulated:"
    tail -n +2 "$GROUND_TRUTH_CSV" | grep ",Malicious," | cut -d',' -f4 | sort | uniq -c | while read count type; do
        printf "  • %s (%d phases)\n" "$type" "$count"
    done

    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Next Steps:"
    echo "  1. Copy $GROUND_TRUTH_CSV to victim machine"
    echo "  2. Ensure victim's prediction CSV is in /opt/ids/evaluation/"
    echo "  3. Run: python3 evaluate_ids.py -g $GROUND_TRUTH_CSV -p predictions.csv"
    echo ""
    echo "----------------------------------------" >> "$TRAFFIC_LOG"
    echo "Completed: $(date -Iseconds)" >> "$TRAFFIC_LOG"
}

################################################################################
# MENU & MAIN
################################################################################

show_menu() {
    echo ""
    echo "Select evaluation scenario:"
    echo "  1) Quick Test (~5 minutes)"
    echo "  2) Standard Test (~30 minutes)"
    echo "  3) Full Test (~1 hour)"
    echo "  4) Custom Test (define your sequence)"
    echo "  5) Single Traffic Type (for debugging)"
    echo "  0) Exit"
    echo ""
    read -p "Enter choice: " choice

    case $choice in
        1) run_quick_test ;;
        2) run_standard_test ;;
        3) run_full_test ;;
        4) run_custom_test ;;
        5)
            echo "Types: benign-http, benign-icmp, benign-mixed,"
            echo "       slowloris, hoic, hulk, goldeneye, syn-flood"
            read -p "Enter type: " type
            read -p "Duration (seconds): " dur
            run_single_type $type ${dur:-60}
            ;;
        0) exit 0 ;;
        *) echo "Invalid choice"; show_menu ;;
    esac
}

show_usage() {
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  quick              Run quick test (~5 min)"
    echo "  standard           Run standard test (~30 min)"
    echo "  full               Run full test (~1 hour)"
    echo "  custom             Interactive custom test"
    echo "  single TYPE [DUR]  Run single traffic type"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_IP          Target IP (default: 10.0.0.13)"
    echo "  PHASE_DURATION     Duration per phase in seconds (default: 60)"
    echo "  COOLDOWN_DURATION  Pause between phases (default: 10)"
    echo ""
    echo "Examples:"
    echo "  TARGET_IP=192.168.1.100 $0 quick"
    echo "  PHASE_DURATION=120 $0 standard"
    echo "  $0 single slowloris 120"
    echo ""
}

# Main
case "${1:-}" in
    quick) run_quick_test ;;
    standard) run_standard_test ;;
    full) run_full_test ;;
    custom) run_custom_test ;;
    single) run_single_type "$2" "${3:-60}" ;;
    --help|-h) show_usage ;;
    "") show_menu ;;
    *) echo "Unknown command: $1"; show_usage; exit 1 ;;
esac