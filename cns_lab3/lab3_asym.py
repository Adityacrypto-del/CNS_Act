"""
CNS Lab 3 - Implementation of Asymmetric Key Cryptographic Algorithms
======================================================================

Implements and benchmarks:
    1. Knapsack (Merkle-Hellman) Cryptosystem
    2. Diffie-Hellman Key Exchange
    3. ElGamal Cryptosystem
    4. ECC / ECDH (Elliptic Curve Diffie-Hellman)

For each algorithm this script measures, over multiple runs and multiple
key/message sizes:
    - Key generation time
    - Encryption time / Key-exchange time
    - Decryption time
    - Peak memory usage (via tracemalloc)
    - Throughput (bytes/sec)
    - Ciphertext size and expansion ratio
    - Mean and standard deviation across runs

Outputs (written to ./lab3_output/):
    - results.csv                  raw results, one row per run
    - summary.csv                  averaged results per (algorithm, size)
    - *.png                        the graphs required by the lab sheet
    - correctness_log.txt          proof that encrypt->decrypt round-trips

Run:  python3 lab3_asym.py
"""

import os
import csv
import time
import random
import secrets
import statistics
import tracemalloc
from math import gcd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import dh, ec

# --------------------------------------------------------------------------
# Configuration - tweak these to change how thorough / slow the run is
# --------------------------------------------------------------------------
RUNS = 10                                   # repetitions per data point
OUTPUT_DIR = "lab3_output"

KNAPSACK_KEY_SIZES = [8, 16, 32, 64]        # bits per knapsack block
DH_KEY_SIZES = [512, 1024, 2048]            # DH / ElGamal prime bit-length
ECC_CURVES = {                              # name -> curve object, roughly by size
    "SECP192R1": ec.SECP192R1(),
    "SECP256R1": ec.SECP256R1(),
    "SECP384R1": ec.SECP384R1(),
    "SECP521R1": ec.SECP521R1(),
}

# Synthetic "files" representing the different input types the lab sheet
# asks for. These are just byte blobs of realistic sizes - the algorithms
# don't care what the bytes originally were.
INPUT_SAMPLES = {
    "text_1KB":   secrets.token_bytes(1 * 1024),
    "image_50KB": secrets.token_bytes(50 * 1024),
    "audio_200KB": secrets.token_bytes(200 * 1024),
    "video_1MB":  secrets.token_bytes(1 * 1024 * 1024),
}

os.makedirs(OUTPUT_DIR, exist_ok=True)
RESULTS = []          # every individual run -> dict
CORRECTNESS_LOG = []  # human-readable proof of correct round-trips


def log_correct(msg):
    CORRECTNESS_LOG.append(msg)
    print(msg)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def timeit():
    """Return a perf_counter() timestamp (seconds, float)."""
    return time.perf_counter()


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def int_to_bytes(i, length):
    return i.to_bytes(length, "big")


def chunk_bytes(data, chunk_size):
    """Split bytes into fixed-size chunks (last chunk padded with zero bytes)."""
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b"\x00" * (chunk_size - len(chunk))
        chunks.append(chunk)
    return chunks


def record(algorithm, phase, size_label, size_value, input_label,
           input_size_bytes, run_idx, elapsed_s, peak_mem_bytes,
           ciphertext_bytes=None):
    row = {
        "algorithm": algorithm,
        "phase": phase,                 # keygen / encrypt / decrypt / key_exchange
        "size_label": size_label,       # e.g. "key_bits" / "curve"
        "size_value": size_value,
        "input_label": input_label,
        "input_size_bytes": input_size_bytes,
        "run": run_idx,
        "time_s": elapsed_s,
        "peak_memory_bytes": peak_mem_bytes,
        "ciphertext_bytes": ciphertext_bytes,
    }
    RESULTS.append(row)
    return row


# ==========================================================================
# 1. KNAPSACK (MERKLE-HELLMAN) CRYPTOSYSTEM
# ==========================================================================
def knapsack_keygen(n_bits):
    """Generate a superincreasing sequence, modulus, multiplier -> keys."""
    # superincreasing sequence
    w = []
    total = 0
    for _ in range(n_bits):
        nxt = total + random.randint(1, 3)
        w.append(nxt)
        total += nxt
    m = total + random.randint(1, 100)          # modulus > sum(w)
    while True:
        r = random.randint(2, m - 1)
        if gcd(r, m) == 1:
            break
    public_key = [(r * wi) % m for wi in w]
    private_key = (w, m, r, pow(r, -1, m))
    return public_key, private_key


def knapsack_encrypt_block(bits, public_key):
    """bits: list of 0/1 of length n_bits."""
    return sum(pk for pk, bit in zip(public_key, bits) if bit)


def knapsack_decrypt_block(cipher_val, private_key):
    w, m, r, r_inv = private_key
    c_prime = (cipher_val * r_inv) % m
    bits = [0] * len(w)
    for i in reversed(range(len(w))):
        if w[i] <= c_prime:
            bits[i] = 1
            c_prime -= w[i]
    return bits


def bytes_to_bitblocks(data, n_bits):
    """Turn bytes into a list of n_bits-length bit lists."""
    bitstring = "".join(f"{byte:08b}" for byte in data)
    pad = (-len(bitstring)) % n_bits
    bitstring += "0" * pad
    return [[int(b) for b in bitstring[i:i + n_bits]]
            for i in range(0, len(bitstring), n_bits)]


def bitblocks_to_bytes(blocks, original_bit_len):
    bitstring = "".join("".join(str(b) for b in blk) for blk in blocks)
    bitstring = bitstring[:original_bit_len]
    pad = (-len(bitstring)) % 8
    bitstring += "0" * pad
    return bytes(int(bitstring[i:i + 8], 2) for i in range(0, len(bitstring), 8))


def run_knapsack():
    for n_bits in KNAPSACK_KEY_SIZES:
        for run in range(RUNS):
            tracemalloc.start()
            t0 = timeit()
            public_key, private_key = knapsack_keygen(n_bits)
            t1 = timeit()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("Knapsack", "keygen", "key_bits", n_bits, "-", 0,
                   run, t1 - t0, peak)

        # encryption / decryption over the sample inputs (use smaller inputs
        # for knapsack since it is a toy/slow scheme block-by-block)
        public_key, private_key = knapsack_keygen(n_bits)
        for input_label, data in INPUT_SAMPLES.items():
            # Cap knapsack demo input to 20KB max so runtime stays sane -
            # the *rate* (throughput) is what matters, not absolute size.
            data = data[:20 * 1024]
            blocks = bytes_to_bitblocks(data, n_bits)
            for run in range(RUNS):
                tracemalloc.start()
                t0 = timeit()
                cipher_vals = [knapsack_encrypt_block(b, public_key) for b in blocks]
                t1 = timeit()
                _, peak_enc = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                cipher_bytes = sum((cv.bit_length() + 7) // 8 for cv in cipher_vals)
                record("Knapsack", "encrypt", "key_bits", n_bits, input_label,
                       len(data), run, t1 - t0, peak_enc, cipher_bytes)

                tracemalloc.start()
                t0 = timeit()
                decoded_blocks = [knapsack_decrypt_block(cv, private_key) for cv in cipher_vals]
                t1 = timeit()
                _, peak_dec = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record("Knapsack", "decrypt", "key_bits", n_bits, input_label,
                       len(data), run, t1 - t0, peak_dec)

            recovered = bitblocks_to_bytes(decoded_blocks, len(data) * 8)
            ok = recovered[:len(data)] == data
            log_correct(f"[Knapsack n={n_bits}] {input_label}: round-trip correct = {ok}")


# ==========================================================================
# 2. DIFFIE-HELLMAN KEY EXCHANGE
# ==========================================================================
def run_dh():
    for key_bits in DH_KEY_SIZES:
        # Parameter generation (finding a safe prime) is expensive and is a
        # one-time group setup, not per-user "key generation" - so it is
        # done once here and NOT included in the timed key-gen measurement.
        params = dh.generate_parameters(generator=2, key_size=key_bits)

        for run in range(RUNS):
            tracemalloc.start()
            t0 = timeit()
            alice_priv = params.generate_private_key()
            bob_priv = params.generate_private_key()
            t1 = timeit()
            _, peak_kg = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("Diffie-Hellman", "keygen", "prime_bits", key_bits, "-", 0,
                   run, t1 - t0, peak_kg)

            tracemalloc.start()
            t0 = timeit()
            alice_shared = alice_priv.exchange(bob_priv.public_key())
            bob_shared = bob_priv.exchange(alice_priv.public_key())
            t1 = timeit()
            _, peak_ex = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("Diffie-Hellman", "key_exchange", "prime_bits", key_bits, "-", 0,
                   run, t1 - t0, peak_ex)

        ok = alice_shared == bob_shared
        log_correct(f"[Diffie-Hellman {key_bits}-bit] shared secrets match = {ok}")


# ==========================================================================
# 3. ELGAMAL CRYPTOSYSTEM  (built on the same style of DH group)
# ==========================================================================
def elgamal_keygen(p, g):
    x = random.randint(2, p - 2)          # private key
    y = pow(g, x, p)                      # public key
    return (p, g, y), x


def elgamal_encrypt_int(m, public_key):
    p, g, y = public_key
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt_int(c1, c2, p, x):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p


def run_elgamal():
    for key_bits in DH_KEY_SIZES:
        params = dh.generate_parameters(generator=2, key_size=key_bits)
        pn = params.parameter_numbers()
        p, g = pn.p, pn.g
        block_size = (key_bits // 8) - 1  # keep message ints < p

        for run in range(RUNS):
            tracemalloc.start()
            t0 = timeit()
            public_key, private_x = elgamal_keygen(p, g)
            t1 = timeit()
            _, peak_kg = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("ElGamal", "keygen", "prime_bits", key_bits, "-", 0,
                   run, t1 - t0, peak_kg)

        public_key, private_x = elgamal_keygen(p, g)
        for input_label, data in INPUT_SAMPLES.items():
            data = data[:20 * 1024]  # keep runtime sane; throughput still valid
            blocks = chunk_bytes(data, block_size)
            for run in range(RUNS):
                tracemalloc.start()
                t0 = timeit()
                ciphertexts = [elgamal_encrypt_int(bytes_to_int(b), public_key) for b in blocks]
                t1 = timeit()
                _, peak_enc = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                cipher_bytes = sum(((c1.bit_length() + 7) // 8) + ((c2.bit_length() + 7) // 8)
                                    for c1, c2 in ciphertexts)
                record("ElGamal", "encrypt", "prime_bits", key_bits, input_label,
                       len(data), run, t1 - t0, peak_enc, cipher_bytes)

                tracemalloc.start()
                t0 = timeit()
                decrypted = [elgamal_decrypt_int(c1, c2, p, private_x) for c1, c2 in ciphertexts]
                t1 = timeit()
                _, peak_dec = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                record("ElGamal", "decrypt", "prime_bits", key_bits, input_label,
                       len(data), run, t1 - t0, peak_dec)

            recovered = b"".join(int_to_bytes(d, block_size) for d in decrypted)
            ok = recovered[:len(data)] == data
            log_correct(f"[ElGamal {key_bits}-bit] {input_label}: round-trip correct = {ok}")


# ==========================================================================
# 4. ECC / ECDH
# ==========================================================================
def run_ecdh():
    for curve_name, curve in ECC_CURVES.items():
        for run in range(RUNS):
            tracemalloc.start()
            t0 = timeit()
            alice_priv = ec.generate_private_key(curve)
            bob_priv = ec.generate_private_key(curve)
            t1 = timeit()
            _, peak_kg = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("ECC/ECDH", "keygen", "curve", curve_name, "-", 0,
                   run, t1 - t0, peak_kg)

            tracemalloc.start()
            t0 = timeit()
            alice_shared = alice_priv.exchange(ec.ECDH(), bob_priv.public_key())
            bob_shared = bob_priv.exchange(ec.ECDH(), alice_priv.public_key())
            t1 = timeit()
            _, peak_ex = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            record("ECC/ECDH", "key_exchange", "curve", curve_name, "-", 0,
                   run, t1 - t0, peak_ex)

        ok = alice_shared == bob_shared
        log_correct(f"[ECDH {curve_name}] shared secrets match = {ok}")


# ==========================================================================
# CSV output
# ==========================================================================
def write_raw_csv():
    path = os.path.join(OUTPUT_DIR, "results.csv")
    fieldnames = ["algorithm", "phase", "size_label", "size_value", "input_label",
                  "input_size_bytes", "run", "time_s", "peak_memory_bytes",
                  "ciphertext_bytes"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(RESULTS)
    print(f"Wrote {path} ({len(RESULTS)} rows)")


def summarize():
    """Group RESULTS by (algorithm, phase, size_value, input_label) and
    compute mean/std time, mean memory, mean ciphertext size, throughput."""
    groups = {}
    for row in RESULTS:
        key = (row["algorithm"], row["phase"], row["size_value"], row["input_label"])
        groups.setdefault(key, []).append(row)

    summary_rows = []
    for (algorithm, phase, size_value, input_label), rows in groups.items():
        times = [r["time_s"] for r in rows]
        mems = [r["peak_memory_bytes"] for r in rows]
        input_size = rows[0]["input_size_bytes"]
        cts = [r["ciphertext_bytes"] for r in rows if r["ciphertext_bytes"] is not None]
        mean_t = statistics.mean(times)
        std_t = statistics.pstdev(times) if len(times) > 1 else 0.0
        mean_mem = statistics.mean(mems)
        mean_ct = statistics.mean(cts) if cts else None
        throughput = (input_size / mean_t) if (input_size > 0 and mean_t > 0) else None
        expansion = (mean_ct / input_size) if (mean_ct and input_size > 0) else None
        summary_rows.append({
            "algorithm": algorithm,
            "phase": phase,
            "size_value": size_value,
            "input_label": input_label,
            "input_size_bytes": input_size,
            "mean_time_s": mean_t,
            "std_time_s": std_t,
            "mean_peak_memory_bytes": mean_mem,
            "mean_ciphertext_bytes": mean_ct,
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


def plot_input_size_vs_time(summary, phase, ylabel, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] != phase or r["input_label"] == "-":
            continue
        by_algo.setdefault(r["algorithm"], []).append((r["input_size_bytes"], r["mean_time_s"]))
    for algo, points in by_algo.items():
        points.sort()
        xs, ys = zip(*points)
        ax.plot(xs, ys, marker="o", label=algo)
    ax.set_xlabel("Input size (bytes)")
    ax.set_ylabel(ylabel)
    ax.set_title(f"Input Size vs {ylabel}")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_keysize_vs_time(summary, phase, filename, title):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] != phase or r["input_label"] != "-":
            continue
        by_algo.setdefault(r["algorithm"], []).append((str(r["size_value"]), r["mean_time_s"]))
    for algo, points in by_algo.items():
        labels = [p[0] for p in points]
        ys = [p[1] for p in points]
        ax.plot(labels, ys, marker="o", label=algo)
    ax.set_xlabel("Key / Parameter size")
    ax.set_ylabel("Time (s)")
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_keysize_vs_memory(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] not in ("keygen", "key_exchange") or r["input_label"] != "-":
            continue
        by_algo.setdefault(r["algorithm"], []).append(
            (str(r["size_value"]), r["mean_peak_memory_bytes"]))
    for algo, points in by_algo.items():
        labels = [p[0] for p in points]
        ys = [p[1] for p in points]
        ax.plot(labels, ys, marker="o", label=algo)
    ax.set_xlabel("Key / Parameter size")
    ax.set_ylabel("Peak memory (bytes)")
    ax.set_title("Key/Param Size vs Memory Usage")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def plot_algo_vs_avg_time(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        by_algo.setdefault(r["algorithm"], []).append(r["mean_time_s"])
    algos = list(by_algo.keys())
    avgs = [statistics.mean(v) for v in by_algo.values()]
    ax.bar(algos, avgs, color=["#4C72B0", "#DD8452", "#55A868", "#C44E52"][:len(algos)])
    ax.set_ylabel("Average time across all operations (s)")
    ax.set_title("Algorithm vs Average Execution Time")
    ax.grid(True, axis="y", alpha=0.3)
    save_plot(fig, filename)


def plot_algo_vs_throughput(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] == "encrypt" and r["throughput_bytes_per_s"]:
            by_algo.setdefault(r["algorithm"], []).append(r["throughput_bytes_per_s"])
    algos = list(by_algo.keys())
    avgs = [statistics.mean(v) for v in by_algo.values()]
    if algos:
        ax.bar(algos, avgs, color=["#4C72B0", "#DD8452"][:len(algos)])
    ax.set_ylabel("Average encryption throughput (bytes/s)")
    ax.set_title("Algorithm vs Throughput (encryption)")
    ax.grid(True, axis="y", alpha=0.3)
    save_plot(fig, filename)


def plot_plaintext_vs_ciphertext(summary, filename):
    fig, ax = plt.subplots(figsize=(7, 5))
    by_algo = {}
    for r in summary:
        if r["phase"] == "encrypt" and r["mean_ciphertext_bytes"]:
            by_algo.setdefault(r["algorithm"], []).append(
                (r["input_size_bytes"], r["mean_ciphertext_bytes"]))
    for algo, points in by_algo.items():
        points.sort()
        xs, ys = zip(*points)
        ax.plot(xs, ys, marker="o", label=algo)
    ax.set_xlabel("Plaintext size (bytes)")
    ax.set_ylabel("Ciphertext size (bytes)")
    ax.set_title("Plaintext Size vs Ciphertext Size")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_plot(fig, filename)


def make_graphs(summary):
    plot_input_size_vs_time(summary, "encrypt", "Encryption Time (s)",
                             "01_input_size_vs_encryption_time.png")
    plot_input_size_vs_time(summary, "decrypt", "Decryption Time (s)",
                             "02_input_size_vs_decryption_time.png")
    plot_keysize_vs_time(summary, "keygen", "03_keysize_vs_keygen_time.png",
                          "Key/Parameter Size vs Key Generation Time")
    plot_keysize_vs_time(summary, "key_exchange",
                          "04_keysize_vs_main_operation_time.png",
                          "Key/Parameter Size vs Key-Exchange Time (DH / ECDH)")
    plot_keysize_vs_memory(summary, "05_keysize_vs_memory.png")
    plot_algo_vs_avg_time(summary, "06_algorithm_vs_avg_time.png")
    plot_algo_vs_throughput(summary, "07_algorithm_vs_throughput.png")
    plot_plaintext_vs_ciphertext(summary, "08_plaintext_vs_ciphertext_size.png")


# ==========================================================================
# Main
# ==========================================================================
if __name__ == "__main__":
    print("Running Knapsack ...")
    run_knapsack()
    print("Running Diffie-Hellman ...")
    run_dh()
    print("Running ElGamal ...")
    run_elgamal()
    print("Running ECC/ECDH ...")
    run_ecdh()

    write_raw_csv()
    summary = summarize()
    make_graphs(summary)

    with open(os.path.join(OUTPUT_DIR, "correctness_log.txt"), "w") as f:
        f.write("\n".join(CORRECTNESS_LOG))

    print("\nAll done. See the '{}' folder for results.csv, summary.csv, "
          "graphs (*.png) and correctness_log.txt".format(OUTPUT_DIR))
