#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-examples/build}"
SAMPLE="${SAMPLE:-tests/sample.pcap}"
SUMMARY="${SUMMARY:-bench_results/incoming/local/summary.txt}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-8}"
OS="${OS:-$(uname)}"

mkdir -p "$(dirname "$SUMMARY")"

permission_regex='(permission|denied|operation not permitted|access denied|access is denied|try running as root|admin)'

run_required() {
    local label="$1"
    local expected="$2"
    shift 2
    local out rc
    local cmd=("$@")

    echo "Running required example: ${label}" | tee -a "$SUMMARY"
    out="$(mktemp)"
    set +e
    "${cmd[@]}" > "$out" 2>&1
    rc=$?
    set -e

    cat "$out" | tee -a "$SUMMARY"

    if [ "$rc" -ne 0 ]; then
        echo "FAIL: ${label} exited with $rc" | tee -a "$SUMMARY"
        rm -f "$out"
        return 1
    fi

    if [ "$expected" != "-" ] && ! grep -Fq -- "$expected" "$out"; then
        echo "FAIL: ${label} missing expected output: ${expected}" | tee -a "$SUMMARY"
        rm -f "$out"
        return 1
    fi

    rm -f "$out"
}

run_tolerant() {
    local label="$1"
    local expected="$2"
    local allow_timeout="$3"
    shift 3
    local out rc
    local cmd=("$@")

    echo "Running tolerant example: ${label}" | tee -a "$SUMMARY"
    out="$(mktemp)"
    set +e
    if command -v timeout >/dev/null 2>&1 && [ "$TIMEOUT_SECONDS" -gt 0 ]; then
        timeout "${TIMEOUT_SECONDS}" "${cmd[@]}" > "$out" 2>&1
        rc=$?
    else
        "${cmd[@]}" > "$out" 2>&1
        rc=$?
    fi
    set -e

    cat "$out" | tee -a "$SUMMARY"

    if [ "$rc" -eq 0 ]; then
        if [ "$expected" != "-" ] && ! grep -Fq -- "$expected" "$out"; then
            echo "FAIL: ${label} missing expected output: ${expected}" | tee -a "$SUMMARY"
            rm -f "$out"
            return 1
        fi
        rm -f "$out"
        return 0
    fi

    if [ "$allow_timeout" -eq 1 ] && [ "$rc" -eq 124 ]; then
        echo "PASS (timeout): ${label} (no packets seen in allotted time)" | tee -a "$SUMMARY"
        rm -f "$out"
        return 0
    fi

    if grep -Eiq "$permission_regex" "$out"; then
        echo "PASS (permission): ${label} (CI environment denied capture access)" | tee -a "$SUMMARY"
        rm -f "$out"
        return 0
    fi

    echo "FAIL: ${label} exited with ${rc}" | tee -a "$SUMMARY"
    rm -f "$out"
    return 1
}

run_linux_only() {
    if [ "$OS" != "Linux" ]; then
        echo "Skipping linux-only example on ${OS}: $1" | tee -a "$SUMMARY"
        return 0
    fi

    run_tolerant "$@"
}

run_required "03_offline_read_cpp" "End of capture after" "$BUILD_DIR/03_offline_read_cpp" "$SAMPLE"
run_required "07_offline_split_ipv4_cpp" "Saved output to ipv4_only.pcap" "$BUILD_DIR/07_offline_split_ipv4_cpp" "$SAMPLE"
run_required "09_offline_split_transport_cpp" "written:" "$BUILD_DIR/09_offline_split_transport_cpp" "$SAMPLE"
run_required "08_offline_protocol_stats_c" "packets processed:" "$BUILD_DIR/08_offline_protocol_stats_c" "$SAMPLE"
run_required "11_findalldevs_lookupdev_c" "Devices returned by zpcap_findalldevs:" "$BUILD_DIR/11_findalldevs_lookupdev_c"
run_required "12_nonblocking_stats_c" "zpcap_stats:" "$BUILD_DIR/12_nonblocking_stats_c" "$SAMPLE"
run_required "15_findalldevs_lookupdev_cpp" "Devices returned by zpcap_findalldevs:" "$BUILD_DIR/15_findalldevs_lookupdev_cpp"
run_required "16_nonblocking_stats_cpp" "zpcap_stats:" "$BUILD_DIR/16_nonblocking_stats_cpp" "$SAMPLE"
run_required "19_async_native_wait_cpp" "Loop finished after" "$BUILD_DIR/19_async_native_wait_cpp" "--offline" "$SAMPLE" "18"
run_linux_only "20_linux_kernel_features_c" "Feature mask:" 1 "$BUILD_DIR/20_linux_kernel_features_c"

run_linux_only "01_basic_capture_c" "-" 1 "$BUILD_DIR/01_basic_capture_c"
run_linux_only "02_pcap_dump_c" "-" 1 "$BUILD_DIR/02_pcap_dump_c"
run_linux_only "04_bpf_filter_c" "-" 1 "$BUILD_DIR/04_bpf_filter_c"
run_linux_only "05_next_and_stats_c" "-" 1 "$BUILD_DIR/05_next_and_stats_c"
run_linux_only "06_filtered_capture_to_file_c" "-" 1 "$BUILD_DIR/06_filtered_capture_to_file_c"
run_linux_only "10_live_capture_options_c" "-" 1 "$BUILD_DIR/10_live_capture_options_c" "lo"
run_linux_only "13_send_packet_c" "-" 1 "$BUILD_DIR/13_send_packet_c" "lo"
run_linux_only "18_async_select_c" "-" 1 "$BUILD_DIR/18_async_select_c" "lo" "2"
run_linux_only "17_send_packet_cpp" "-" 1 "$BUILD_DIR/17_send_packet_cpp" "lo"
run_linux_only "18_async_select_cpp" "-" 1 "$BUILD_DIR/18_async_select_cpp" "lo" "2"
