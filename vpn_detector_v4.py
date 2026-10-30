#!/usr/bin/env python3
"""
VPN Detector v4 -- Protocol-agnostic dual-track inner TCP detection.


Usage:
    python vpn_detector_v4.py --dataset calibration --k_max 9 --round 0
    python vpn_detector_v4.py --dataset standard    --k_max 9 --round 0
    python vpn_detector_v4.py --dataset openworld   --k_max 9 --round 0
"""

import json
import argparse
import datetime
import time
from pathlib import Path
from collections import namedtuple

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "handshake_processed"
VPN_PROC  = DATA_DIR / "handshake_VPN_processed"
NVPN_PROC = DATA_DIR / "handshake_nonVPN_processed"

KNOWN_VPN_FOLDERS = [
    "web_openvpnTCP", "web_openvpnUDP", "web_wireguard",
    "ssh_openvpnTCP", "ssh_openvpnUDP", "ssh_wireguard",
    "scp_openvpnTCP", "scp_openvpnUDP", "scp_wireguard",
]
UNKNOWN_VPN_FOLDERS = [
    "web_ikev2",     "web_lightaway",  "web_nordlynx",
    "ssh_ikev2",     "ssh_lightaway",  "ssh_nordlynx",
    "scp_ikev2",     "scp_lightaway",  "scp_nordlynx",
]
SELF_NONVPN_FOLDERS = ["web_nonVPN", "ssh_nonVPN", "scp_nonVPN"]
CIC_FOLDER = "CIC_monday"

CAL_PER_FOLDER = 1000

Burst = namedtuple("Burst", ["dir", "bytes", "pkts", "start", "end"])


def build_bursts(data_pkts):
    bursts = []
    cur_dir   = data_pkts[0]["direction"]
    cur_bytes = data_pkts[0]["size"]
    cur_pkts  = 1
    cur_start = data_pkts[0]["ts"]
    prev_ts   = data_pkts[0]["ts"]
    for p in data_pkts[1:]:
        gap = p["ts"] - prev_ts
        if p["direction"] != cur_dir or gap > 0.010:
            bursts.append(Burst(cur_dir, cur_bytes, cur_pkts, cur_start, prev_ts))
            cur_dir   = p["direction"]
            cur_bytes = p["size"]
            cur_pkts  = 1
            cur_start = p["ts"]
        else:
            cur_bytes += p["size"]
            cur_pkts  += 1
        prev_ts = p["ts"]
    bursts.append(Burst(cur_dir, cur_bytes, cur_pkts, cur_start, prev_ts))
    return bursts


def find_inner_tcp_3whs(bursts, k_max=9):

    window = bursts[:k_max]

    for k in range(len(window) - 2):
        bk, bk1, bk2 = window[k], window[k+1], window[k+2]

        # Direction: alternating (SYN C->S, SYN-ACK S->C, ACK C->S)
        if not (bk.dir == bk2.dir and bk.dir != bk1.dir):
            continue

        # First two bursts: encapsulated SYN and SYN-ACK.
        # Must be in control-size range -- not noise, not bulk data.
        if not (40 <= bk.bytes <= 300):
            continue
        if not (40 <= bk1.bytes <= 300):
            continue
        if bk.pkts > 2 or bk1.pkts > 2:
            continue

        # SYN and SYN-ACK must be similar in size.
        pair_max = max(bk.bytes, bk1.bytes)
        pair_min = min(bk.bytes, bk1.bytes)
        if pair_max > pair_min * 2.5:
            continue

        # Third burst: encapsulated ACK.
        if bk2.bytes > 1000:
            continue
        if bk2.pkts > 4:
            continue

        # Timing
        if bk1.start - bk.start > 2.000:
            continue
        if bk2.start - bk1.start > 2.000:
            continue

        b    = float(pair_min)
        rtt0 = max(0.010, min(0.200, bk1.start - bk.start))
        tau  = max(0.040, min(0.200, 4 * rtt0))
        is_pure_3whs = (bk2.bytes <= 220)

        return (k, b, rtt0, tau, is_pure_3whs)

    return None


def causal_ack_validation(bursts, k, b, tau):

    N = N_cs = N_sc = 0
    data_burst_count = 0
    j = k + 3
    data_threshold = max(2 * b, b + 160)

    # Relative ACK window: scales with b, protocol-agnostic.
    ack_lo = b * 0.5
    ack_hi = b * 2.0

    while j < len(bursts):
        bj = bursts[j]
        if bj.bytes >= data_threshold:
            data_burst_count += 1
            if j + 1 < len(bursts):
                bj1 = bursts[j + 1]
                if (bj1.dir != bj.dir
                        and ack_lo <= bj1.bytes <= ack_hi
                        and bj1.pkts <= 2
                        and (bj1.start - bj.end) <= tau):
                    N += 1
                    if bj.dir == 0:
                        N_cs += 1
                    else:
                        N_sc += 1
                    j += 2
                    continue
        j += 1

    return N, N_cs, N_sc


def find_ack_only_pattern(bursts, min_pairs=4):

    ack_sizes = []
    n_cs = 0
    n_sc = 0

    i = 0
    while i < len(bursts) - 1:
        bj  = bursts[i]
        bj1 = bursts[i + 1]
        if (bj.bytes > 200
                and bj1.dir != bj.dir
                and 30 <= bj1.bytes <= 300
                and bj.bytes > bj1.bytes * 3      # data burst >> ACK burst
                and bj1.pkts <= 2
                and (bj1.start - bj.end) <= 0.200):
            ack_sizes.append(bj1.bytes)
            if bj.dir == 0:
                n_cs += 1
            else:
                n_sc += 1
            i += 2
            continue
        i += 1

    if len(ack_sizes) < min_pairs:
        return None

    b_est = sum(ack_sizes) / len(ack_sizes)


    return (b_est, len(ack_sizes), n_cs, n_sc)


def classify_flow(packets, k_max=9, flow_protocol=None):

    data_pkts = [p for p in packets if p["is_data_carrying"]]
    if len(data_pkts) < 6:
        return 0

    bursts = build_bursts(data_pkts)

    result = find_inner_tcp_3whs(bursts, k_max=k_max)
    if result is not None:
        k, b, rtt0, tau, is_pure_3whs = result
        N, N_cs, N_sc = causal_ack_validation(bursts, k, b, tau)
        has_data    = any(bx.bytes >= b + 400 for bx in bursts)
        small_ratio = sum(1 for bx in bursts if bx.bytes <= b + 32) / len(bursts)
        # Require at least 2 causal ACK pairs: one request-response cycle in
        # a non-VPN TLS/HTTP flow produces exactly N=1; a VPN tunnel carries
        # multiple inner request-response cycles, giving N >= 2.
        if (N >= 2 and N_sc >= 1
                and has_data
                and small_ratio < 0.85):
            return 1


    if flow_protocol is not None and flow_protocol != "udp":
        return 0

    ack_result = find_ack_only_pattern(bursts)
    if ack_result is not None:
        b_est, n_pairs, n_cs_a, n_sc_a = ack_result
        has_data_a    = any(bx.bytes >= b_est + 400 for bx in bursts)
        small_ratio_a = sum(1 for bx in bursts if bx.bytes <= b_est + 32) / len(bursts)
        # Require data in at least one direction (OR, not AND): VPN tunnels
        # carrying unidirectional applications (SCP upload/download) will
        # only show ACK pairs from one side.  Both sides are still required
        # for Track B (which uses a detected 3WHS to anchor the scan).
        # Lowered from 12 to 8: shorter web VPN sessions (fewer round trips)
        # also show the consistent data→ACK rhythm and should be detectable.
        if ((n_cs_a >= 1 or n_sc_a >= 1)
                and has_data_a
                and len(bursts) >= 8
                and small_ratio_a < 0.80):
            return 1

    return 0


def get_flows(dataset):
    flows = []
    if dataset == "calibration":
        for fn in KNOWN_VPN_FOLDERS:
            d = VPN_PROC / fn
            if not d.exists():
                print("WARNING: %s not found" % d); continue
            for f in sorted(d.glob("*.json"))[:CAL_PER_FOLDER]:
                flows.append((f, 1, fn))
        for fn in SELF_NONVPN_FOLDERS:
            d = NVPN_PROC / fn
            if not d.exists():
                print("WARNING: %s not found" % d); continue
            for f in sorted(d.glob("*.json")):
                flows.append((f, 0, fn))

    elif dataset == "standard":
        for fn in KNOWN_VPN_FOLDERS:
            d = VPN_PROC / fn
            if not d.exists():
                print("WARNING: %s not found" % d); continue
            for f in sorted(d.glob("*.json"))[CAL_PER_FOLDER:]:
                flows.append((f, 1, fn))
        d = NVPN_PROC / CIC_FOLDER
        if d.exists():
            for f in sorted(d.glob("*.json")):
                flows.append((f, 0, CIC_FOLDER))
        else:
            print("WARNING: %s not found" % d)

    elif dataset == "openworld":
        for fn in UNKNOWN_VPN_FOLDERS:
            d = VPN_PROC / fn
            if not d.exists():
                print("WARNING: %s not found" % d); continue
            for f in sorted(d.glob("*.json")):
                flows.append((f, 1, fn))

    return flows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["calibration", "standard", "openworld"],
                        default="calibration")
    parser.add_argument("--k_max", type=int, default=9,
                        help="Scan window for inner TCP 3WHS (default: 9)")
    parser.add_argument("--round", type=int, default=0)
    args = parser.parse_args()
    dataset = args.dataset
    k_max   = args.k_max
    round_n = args.round

    results_dir = BASE_DIR / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    flows = get_flows(dataset)
    total = len(flows)
    print("Dataset: %s  |  k_max: %d  |  Round: %d  |  Flows: %d" % (
        dataset, k_max, round_n, total))
    if not flows:
        print("No flows found."); return

    TP = FP = TN = FN = 0
    read_errors = 0
    folder_stats = {}
    fp_files = []
    t0 = time.time()

    for i, (fpath, label, subfolder) in enumerate(flows):
        if i % 5000 == 0 and i > 0:
            elapsed = time.time() - t0
            print("  %d/%d  (%.0fs, %.0f flows/s)" % (i, total, elapsed, i/elapsed),
                  flush=True)
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            flow_proto = data.get("flow", {}).get("protocol", None)
            pred = classify_flow(data["packets"], k_max=k_max, flow_protocol=flow_proto)
        except Exception as exc:
            read_errors += 1
            if read_errors <= 5:
                print("WARNING: failed to process %s: %s" % (fpath, exc))
            pred = 0

        if subfolder not in folder_stats:
            folder_stats[subfolder] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "label": label}
        st = folder_stats[subfolder]
        if label == 1:
            if pred == 1: TP += 1; st["TP"] += 1
            else:         FN += 1; st["FN"] += 1
        else:
            if pred == 1:
                FP += 1; st["FP"] += 1
                fp_files.append(str(fpath))
            else:
                TN += 1; st["TN"] += 1

    elapsed = time.time() - t0
    speed   = total / elapsed

    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    Pre = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    F1  = 2 * Pre * TPR / (Pre + TPR) if (Pre + TPR) > 0 else 0.0

    print()
    print("=" * 60)
    print("DATASET=%s  K_MAX=%d  ROUND=%d  (v4: dual-track)" % (
        dataset.upper(), k_max, round_n))
    print("=" * 60)
    print("TP=%d  FP=%d  TN=%d  FN=%d" % (TP, FP, TN, FN))
    print("TPR=%.4f  FPR=%.4f  Precision=%.4f  F1=%.4f" % (TPR, FPR, Pre, F1))
    print("Processing errors: %d" % read_errors)
    print("Elapsed: %.1fs  (%.0f flows/s)" % (elapsed, speed))
    print()
    print("Per-folder breakdown:")
    for fn, st in sorted(folder_stats.items()):
        tp, fp, tn, fn_ = st["TP"], st["FP"], st["TN"], st["FN"]
        if st["label"] == 1:
            r    = tp / (tp + fn_) if (tp + fn_) > 0 else 0.0
            rate = "TPR=%.4f" % r
        else:
            r    = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            rate = "FPR=%.4f" % r
        print("  %-22s  TP=%5d  FP=%5d  TN=%6d  FN=%5d  %s" % (
            fn, tp, fp, tn, fn_, rate))

    today = datetime.date.today().isoformat()
    result_path = results_dir / ("v4_kmax%d_%s_r%d_results.md" % (k_max, dataset, round_n))

    with open(result_path, "w", encoding="utf-8") as f:
        f.write("# VPN Detector v4 | Dataset=%s | k_max=%d | Round=%d | Date=%s\n\n" % (
            dataset, k_max, round_n, today))
        f.write("## Algorithm: Protocol-agnostic dual-track (Track B: 3WHS+ACK validation, Track A: ACK-consistency)\n\n")
        f.write("Processing errors: %d\n\n" % read_errors)
        f.write("## Confusion Matrix\n\n")
        f.write("| TP | FP | TN | FN |\n|---|---|---|---|\n")
        f.write("| %d | %d | %d | %d |\n\n" % (TP, FP, TN, FN))
        f.write("## Metrics\n\n")
        f.write("| TPR | FPR | Precision | F1 |\n|---|---|---|---|\n")
        f.write("| %.4f | %.4f | %.4f | %.4f |\n\n" % (TPR, FPR, Pre, F1))
        f.write("## Per-Folder Breakdown\n\n")
        f.write("| Folder | TP | FP | TN | FN | Rate |\n|---|---|---|---|---|---|\n")
        for fn, st in sorted(folder_stats.items()):
            tp, fp, tn, fn_ = st["TP"], st["FP"], st["TN"], st["FN"]
            if st["label"] == 1:
                r    = tp / (tp + fn_) if (tp + fn_) > 0 else 0.0
                rate = "TPR=%.4f" % r
            else:
                r    = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                rate = "FPR=%.4f" % r
            f.write("| %s | %d | %d | %d | %d | %s |\n" % (fn, tp, fp, tn, fn_, rate))
        f.write("\n## Efficiency\n\nElapsed: %.1fs | Speed: %.0f flows/s\n" % (elapsed, speed))
        if fp_files:
            f.write("\n## FP Files (first 20)\n\n")
            for fp_f in fp_files[:20]:
                f.write("- %s\n" % fp_f)

    print()
    print("Saved: %s" % result_path)
    print("=" * 60)


if __name__ == "__main__":
    main()
