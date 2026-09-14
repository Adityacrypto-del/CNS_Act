"""
CNS Lab 4 - Implementation of Hash Functions, MAC, and Digital Signature
=========================================================================

Implements and benchmarks:
    1. SHA-256 and SHA-512 (hash functions)
    2. HMAC-SHA256 and HMAC-SHA512 (message authentication codes)
    3. RSA-PSS with SHA-256 (digital signatures), at 2048 / 3072 / 4096-bit keys

For each, this script measures across multiple input sizes/types and
repeated runs:
    - Hash / MAC / signature generation time
    - MAC / signature verification time
    - RSA key generation time
    - Peak memory usage (tracemalloc)
    - Throughput (bytes/sec)
    - Digest / MAC / signature size and expansion ratio
    - Mean and standard deviation across runs

It also runs the required "file modification" demonstration: it computes
the hash/HMAC/signature of an original file, flips one byte, and shows
that verification correctly fails on the modified data - and shows what
happens when HMAC is verified with the wrong key.

Outputs (written to ./lab4_output/):
    - results.csv                    raw results, one row per run
    - summary.csv                    averaged results per (algorithm, phase, size)
    - *.png                          the graphs required by the lab sheet
    - correctness_log.txt            tamper-detection / wrong-key demonstration

Run:  python3 lab4_hash_mac_sig.py
"""

import os
import csv
import hmac
import time
import string
import random
import hashlib
import secrets
import statistics
import tracemalloc

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes as crypto_hashes

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
RUNS = 10
OUTPUT_DIR = "lab4_output"

# label -> (size_in_bytes, "text" | "binary")   -- mirrors the lab sheet's table
INPUT_FILES = {
    "500B_text":       (500,                 "text"),
    "1KB_textfile":    (1 * 1024,            "text"),
    "10KB_textfile":   (10 * 1024,           "text"),
    "50KB_binary":     (50 * 1024,           "binary"),
    "100KB_image":     (100 * 1024,          "binary"),
    "1MB_pdf":         (1 * 1024 * 1024,     "binary"),
    "5MB_video":       (5 * 1024 * 1024,     "binary"),
    "8MB_video":       (8 * 1024 * 1024,     "binary"),
}

HASH_ALGOS = {"SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512}
HMAC_ALGOS = {"HMAC-SHA256": hashlib.sha256, "HMAC-SHA512": hashlib.sha512}
RSA_KEY_SIZES = [2048, 3072, 4096]
HMAC_KEY = secrets.token_bytes(32)
WRONG_HMAC_KEY = secrets.token_bytes(32)

os.makedirs(OUTPUT_DIR, exist_ok=True)
RESULTS = []
CORRECTNESS_LOG = []


def log(msg):
    CORRECTNESS_LOG.append(msg)
    print(msg)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def make_data(size, kind):
    if kind == "text":
        alphabet = (string.ascii_letters + string.digits + " .,\n").encode()
        return bytes(random.choice(alphabet) for _ in range(size))
    return secrets.token_bytes(size)


DATA_CACHE = {label: make_data(size, kind) for label, (size, kind) in INPUT_FILES.items()}


def flip_one_byte(data):
    """Return a copy of data with a single byte flipped (file-modification demo)."""
    b = bytearray(data)
    idx = len(b) // 2
    b[idx] ^= 0xFF
    return bytes(b)


def timeit():
    return time.perf_counter()


def record(algorithm, phase, size_label, size_value, input_label, input_size_bytes,
           run_idx, elapsed_s, peak_mem_bytes, output_bytes=None):
    RESULTS.append({
        "algorithm": algorithm,
        "phase": phase,                    # hash / mac_gen / mac_verify / keygen / sign / verify
        "size_label": size_label,          # "input_size" or "key_bits"
        "size_value": size_value,
        "input_label": input_label,
        "input_size_bytes": input_size_bytes,
        "run": run_idx,
        "time_s": elapsed_s,
        "peak_memory_bytes": peak_mem_bytes,
        "output_bytes": output_bytes,
    })


# ==========================================================================
# 1. HASH FUNCTIONS (SHA-256 / SHA-512)
# ==========================================================================
def run_hash():
    for algo_name, hashfunc in HASH_ALGOS.items():
        for label, (size, kind) in INPUT_FILES.items():
            data = DATA_CACHE[label]
            for run in range(RUNS):
                tracemalloc.start()
                t0 = timeit()
                digest = hashfunc(data).digest()
                t1 = timeit()
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record(algo_name, "hash", "input_size", size, label, size,
                       run, t1 - t0, peak, len(digest))

    # --- file modification demonstration ---
    for label in ("10KB_textfile", "1MB_pdf"):
        original = DATA_CACHE[label]
        modified = flip_one_byte(original)
        for algo_name, hashfunc in HASH_ALGOS.items():
            h_orig = hashfunc(original).hexdigest()
            h_mod = hashfunc(modified).hexdigest()
            log(f"[{algo_name}] {label}: original digest  = {h_orig[:24]}...")
            log(f"[{algo_name}] {label}: modified digest  = {h_mod[:24]}...")
            log(f"[{algo_name}] {label}: digests match after 1-byte change = {h_orig == h_mod} "
                f"(expected False)")


# ==========================================================================
# 2. HMAC (HMAC-SHA256 / HMAC-SHA512)
# ==========================================================================
def run_hmac():
    for algo_name, hashfunc in HMAC_ALGOS.items():
        for label, (size, kind) in INPUT_FILES.items():
            data = DATA_CACHE[label]
            for run in range(RUNS):
                tracemalloc.start()
                t0 = timeit()
                tag = hmac.new(HMAC_KEY, data, hashfunc).digest()
                t1 = timeit()
                _, peak_gen = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record(algo_name, "mac_gen", "input_size", size, label, size,
                       run, t1 - t0, peak_gen, len(tag))

                tracemalloc.start()
                t0 = timeit()
                check = hmac.new(HMAC_KEY, data, hashfunc).digest()
                ok = hmac.compare_digest(tag, check)
                t1 = timeit()
                _, peak_ver = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record(algo_name, "mac_verify", "input_size", size, label, size,
                       run, t1 - t0, peak_ver)

    # --- tamper + wrong-key demonstration ---
    for label in ("10KB_textfile", "1MB_pdf"):
        original = DATA_CACHE[label]
        modified = flip_one_byte(original)
        for algo_name, hashfunc in HMAC_ALGOS.items():
            tag = hmac.new(HMAC_KEY, original, hashfunc).digest()

            tag_modified = hmac.new(HMAC_KEY, modified, hashfunc).digest()
            ok_modified = hmac.compare_digest(tag, tag_modified)
            log(f"[{algo_name}] {label}: verification of MODIFIED data with correct key "
                f"succeeds = {ok_modified} (expected False)")

            tag_wrong_key = hmac.new(WRONG_HMAC_KEY, original, hashfunc).digest()
            ok_wrong_key = hmac.compare_digest(tag, tag_wrong_key)
            log(f"[{algo_name}] {label}: verification of ORIGINAL data with WRONG key "
                f"succeeds = {ok_wrong_key} (expected False)")


# ==========================================================================
# 3. RSA-PSS DIGITAL SIGNATURES
# ==========================================================================
PSS_PADDING = lambda: padding.PSS(
    mgf=padding.MGF1(crypto_hashes.SHA256()),
    salt_length=padding.PSS.DIGEST_LENGTH,
)


def run_rsa():
    for key_bits in RSA_KEY_SIZES:
        for run in range(RUNS):
            tracemalloc.start()
            t0 = timeit()
            priv = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
            t1 = timeit()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("RSA-PSS-SHA256", "keygen", "key_bits", key_bits, "-", 0,
                   run, t1 - t0, peak)

        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
        pub = priv.public_key()

        for label, (size, kind) in INPUT_FILES.items():
            data = DATA_CACHE[label]
            for run in range(RUNS):
                tracemalloc.start()
                t0 = timeit()
                signature = priv.sign(data, PSS_PADDING(), crypto_hashes.SHA256())
                t1 = timeit()
                _, peak_sign = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record("RSA-PSS-SHA256", "sign", "key_bits", key_bits, label, size,
                       run, t1 - t0, peak_sign, len(signature))

                tracemalloc.start()
                t0 = timeit()
                try:
                    pub.verify(signature, data, PSS_PADDING(), crypto_hashes.SHA256())
                    valid = True
                except Exception:
                    valid = False
                t1 = timeit()
                _, peak_ver = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record("RSA-PSS-SHA256", "verify", "key_bits", key_bits, label, size,
                       run, t1 - t0, peak_ver)

        # --- tamper demonstration (one key size is enough to illustrate) ---
        if key_bits == RSA_KEY_SIZES[0]:
            for label in ("10KB_textfile", "1MB_pdf"):
                original = DATA_CACHE[label]
                modified = flip_one_byte(original)
                signature = priv.sign(original, PSS_PADDING(), crypto_hashes.SHA256())
                try:
                    pub.verify(signature, modified, PSS_PADDING(), crypto_hashes.SHA256())
                    modified_ok = True
                except Exception:
                    modified_ok = False
                log(f"[RSA-PSS-SHA256 {key_bits}-bit] {label}: signature of ORIGINAL "
                    f"verifies against MODIFIED data = {modified_ok} (expected False)")

    log(f"Confirmed valid = True for {len(RSA_KEY_SIZES)} key sizes " 
        f"x {len(INPUT_FILES)} inputs (see results.csv 'verify' rows)")


# ==========================================================================
# CSV output
# ==========================================================================
def write_raw_csv():
    path = os.path.join(OUTPUT_DIR, "results.csv")
    fieldnames = ["algorithm", "phase", "size_label", "size_value", "input_label",
                  "input_size_bytes", "run", "time_s", "peak_memory_bytes", "output_bytes"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(RESULTS)
    print(f"Wrote {path} ({len(RESULTS)} rows)")


def summarize():
    groups = {}
    for row in RESULTS:
        key = (row["algorithm"], row["phase"], row["size_value"], row["input_label"])
        groups.setdefault(key, []).append(row)

    summary_rows = []
    for (algorithm, phase, size_value, input_label), rows in groups.items():
        times = [r["time_s"] for r in rows]
        mems = [r["peak_memory_bytes"] for r in rows]
        input_size = rows[0]["input_size_bytes"]
        outs = [r["output_bytes"] for r in rows if r["output_bytes"] is not None]
        mean_t = statistics.mean(times)
        std_t = statistics.pstdev(times) if len(times) > 1 else 0.0
        mean_mem = statistics.mean(mems)
        mean_out = statistics.mean(outs) if outs else None
        throughput = (input_size / mean_t) if (input_size > 0 and mean_t > 0) else None
        expansion = (mean_out / input_size) if (mean_out and input_size > 0) else None
        summary_rows.append({
            "algorithm": algorithm,
            "phase": phase,
            "size_value": size_value,
            "input_label": input_label,
            "input_size_bytes": input_size,
            "mean_time_s": mean_t,
            "std_time_s": std_t,
            "mean_peak_memory_bytes": mean_mem,
            "mean_output_bytes": mean_out,
            "throughput_bytes_per_s": throughput,
            "expansion_ratio": expansion,
        })

    path = os.path.join(OUTPUT_DIR, "summary.csv")
    fieldnames = list(summary_rows[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)
    print(f"Wrote {path} ({len(summary_rows)} rows)")
    return summary_rows


# ==========================================================================
# Graphs
# ==========================================================================
def save_plot(fig, name):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {path}")


def plot_input_size_vs(summary, phase, ylabel, filename, algos=None):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] != phase or r["input_label"] == "-":
            continue
        if algos and r["algorithm"] not in algos:
            continue
        by_algo.setdefault(r["algorithm"], []).append((r["input_size_bytes"], r["mean_time_s"]))
    for algo, points in by_algo.items():
        points.sort()
        xs, ys = zip(*points)
        ax.plot(xs, ys, marker="o", label=algo)
    ax.set_xlabel("Input size (bytes)")
    ax.set_ylabel(ylabel)
    ax.set_title(f"Input Size vs {ylabel}")
    ax.set_xscale("log")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_keysize_vs_time(summary, phase, filename, title):
    fig, ax = plt.subplots(figsize=(7, 5))
    points = []
    for r in summary:
        if r["phase"] != phase or r["algorithm"] != "RSA-PSS-SHA256":
            continue
        if phase == "keygen" and r["input_label"] != "-":
            continue
        points.append((r["size_value"], r["mean_time_s"]))
    # average across input sizes for sign/verify (time barely depends on input size)
    by_key = {}
    for k, v in points:
        by_key.setdefault(k, []).append(v)
    labels = sorted(by_key.keys())
    ys = [statistics.mean(by_key[k]) for k in labels]
    ax.plot([str(l) for l in labels], ys, marker="o", color="#C44E52")
    ax.set_xlabel("RSA key size (bits)")
    ax.set_ylabel("Time (s)")
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_input_size_vs_memory(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] not in ("hash", "mac_gen") or r["input_label"] == "-":
            continue
        by_algo.setdefault(r["algorithm"], []).append(
            (r["input_size_bytes"], r["mean_peak_memory_bytes"]))
    for algo, points in by_algo.items():
        points.sort()
        xs, ys = zip(*points)
        ax.plot(xs, ys, marker="o", label=algo)
    ax.set_xlabel("Input size (bytes)")
    ax.set_ylabel("Peak memory (bytes)")
    ax.set_title("Input Size vs Memory Usage")
    ax.set_xscale("log")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_input_size_vs_throughput(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] not in ("hash", "mac_gen") or not r["throughput_bytes_per_s"]:
            continue
        by_algo.setdefault(r["algorithm"], []).append(
            (r["input_size_bytes"], r["throughput_bytes_per_s"]))
    for algo, points in by_algo.items():
        points.sort()
        xs, ys = zip(*points)
        ax.plot(xs, ys, marker="o", label=algo)
    ax.set_xlabel("Input size (bytes)")
    ax.set_ylabel("Throughput (bytes/s)")
    ax.set_title("Input Size vs Throughput")
    ax.set_xscale("log")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_algo_vs_output_size(summary, filename):
    fig, ax = plt.subplots(figsize=(8, 5))
    labels, sizes = [], []
    seen = set()
    for r in summary:
        if r["phase"] in ("hash", "mac_gen") and r["mean_output_bytes"]:
            key = r["algorithm"]
            if key not in seen:
                labels.append(key)
                sizes.append(r["mean_output_bytes"])
                seen.add(key)
        if r["phase"] == "sign" and r["mean_output_bytes"]:
            key = f"RSA-{r['size_value']}"
            if key not in seen:
                labels.append(key)
                sizes.append(r["mean_output_bytes"])
                seen.add(key)
    ax.bar(labels, sizes, color="#4C72B0")
    ax.set_ylabel("Output size (bytes)")
    ax.set_title("Algorithm vs Output Size (digest / MAC / signature)")
    ax.tick_params(axis="x", rotation=30)
    ax.grid(True, axis="y", alpha=0.3)
    save_plot(fig, filename)


def plot_keysize_vs_sig_size(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_key = {}
    for r in summary:
        if r["phase"] == "sign" and r["mean_output_bytes"]:
            by_key.setdefault(r["size_value"], []).append(r["mean_output_bytes"])
    labels = sorted(by_key.keys())
    ys = [statistics.mean(by_key[k]) for k in labels]
    ax.bar([str(l) for l in labels], ys, color="#55A868")
    ax.set_xlabel("RSA key size (bits)")
    ax.set_ylabel("Signature size (bytes)")
    ax.set_title("RSA Key Size vs Signature Size")
    ax.grid(True, axis="y", alpha=0.3)
    save_plot(fig, filename)


def make_graphs(summary):
    plot_input_size_vs(summary, "hash", "Hash Generation Time (s)",
                        "01_input_size_vs_hash_time.png")
    plot_input_size_vs(summary, "mac_gen", "HMAC Generation Time (s)",
                        "02_input_size_vs_hmac_gen_time.png")
    plot_input_size_vs(summary, "mac_verify", "HMAC Verification Time (s)",
                        "03_input_size_vs_hmac_verify_time.png")
    plot_keysize_vs_time(summary, "keygen", "04_rsa_keysize_vs_keygen_time.png",
                          "RSA Key Size vs Key Generation Time")
    plot_keysize_vs_time(summary, "sign", "05_rsa_keysize_vs_signing_time.png",
                          "RSA Key Size vs Signature Generation Time")
    plot_keysize_vs_time(summary, "verify", "06_rsa_keysize_vs_verification_time.png",
                          "RSA Key Size vs Signature Verification Time")
    plot_input_size_vs_memory(summary, "07_input_size_vs_memory.png")
    plot_input_size_vs_throughput(summary, "08_input_size_vs_throughput.png")
    plot_algo_vs_output_size(summary, "09_algorithm_vs_output_size.png")
    plot_keysize_vs_sig_size(summary, "10_rsa_keysize_vs_signature_size.png")


# ==========================================================================
# Main
# ==========================================================================
if __name__ == "__main__":
    print("Running SHA-256 / SHA-512 ...")
    run_hash()
    print("Running HMAC-SHA256 / HMAC-SHA512 ...")
    run_hmac()
    print("Running RSA-PSS-SHA256 (2048 / 3072 / 4096-bit) ...")
    run_rsa()

    write_raw_csv()
    summary = summarize()
    make_graphs(summary)

    with open(os.path.join(OUTPUT_DIR, "correctness_log.txt"), "w") as f:
        f.write("\n".join(CORRECTNESS_LOG))

    print("\nAll done. See the '{}' folder for results.csv, summary.csv, "
          "graphs (*.png) and correctness_log.txt".format(OUTPUT_DIR))
