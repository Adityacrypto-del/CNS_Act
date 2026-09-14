import os
import time
import csv
import matplotlib.pyplot as plt
from generate_samples import main as generate_samples_main, SAMPLES_DIR
from symmetric_crypto import KEYS, get_iv_or_nonce, encrypt_data, decrypt_data

OUTPUT_DIR = os.path.dirname(__file__)
GRAPHS_DIR = os.path.join(OUTPUT_DIR, "graphs")
ENCRYPTED_DIR = os.path.join(OUTPUT_DIR, "encrypted_files")
DECRYPTED_DIR = os.path.join(OUTPUT_DIR, "decrypted_files")

os.makedirs(GRAPHS_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

ALGORITHMS = ["AES", "DES", "3DES", "Blowfish", "ChaCha20"]
FILE_TYPES = ["Text", "Image", "Video"]
SIZES = ["Small", "Medium", "Large"]

def run_benchmarks():
    # Ensure sample files exist
    generate_samples_main()
    
    results = []
    
    print("\n==================================================================================")
    print("                     STARTING CNS LAB 2 BENCHMARKING SUITE                        ")
    print("==================================================================================\n")
    
    for file_type in FILE_TYPES:
        for size in SIZES:
            ext = ".txt" if file_type == "Text" else (".png" if file_type == "Image" else ".mp4")
            sample_filename = f"{file_type.lower()}_{size.lower()}{ext}"
            sample_path = os.path.join(SAMPLES_DIR, sample_filename)
            
            if not os.path.exists(sample_path):
                print(f"Warning: File {sample_path} not found. Skipping.")
                continue
                
            with open(sample_path, "rb") as f:
                plaintext = f.read()
                
            orig_size_bytes = len(plaintext)
            orig_size_mb = orig_size_bytes / (1024 * 1024)
            
            for algo in ALGORITHMS:
                key = KEYS[algo]
                iv_or_nonce = get_iv_or_nonce(algo)
                
                # --- Encryption ---
                start_enc = time.perf_counter()
                ciphertext = encrypt_data(algo, plaintext, key, iv_or_nonce)
                end_enc = time.perf_counter()
                enc_time = end_enc - start_enc
                
                enc_filename = f"{algo}_{file_type}_{size}_encrypted.bin"
                enc_filepath = os.path.join(ENCRYPTED_DIR, enc_filename)
                with open(enc_filepath, "wb") as f:
                    f.write(ciphertext)
                enc_size_bytes = len(ciphertext)
                
                # --- Decryption ---
                start_dec = time.perf_counter()
                decrypted = decrypt_data(algo, ciphertext, key, iv_or_nonce)
                end_dec = time.perf_counter()
                dec_time = end_dec - start_dec
                
                dec_filename = f"{algo}_{file_type}_{size}_decrypted{ext}"
                dec_filepath = os.path.join(DECRYPTED_DIR, dec_filename)
                with open(dec_filepath, "wb") as f:
                    f.write(decrypted)
                
                # --- Verification ---
                is_valid = (decrypted == plaintext)
                
                # --- Throughput (MB/s) ---
                enc_throughput = orig_size_mb / enc_time if enc_time > 0 else 0
                dec_throughput = orig_size_mb / dec_time if dec_time > 0 else 0
                avg_throughput = orig_size_mb / ((enc_time + dec_time) / 2) if (enc_time + dec_time) > 0 else 0
                
                results.append({
                    "Algorithm": algo,
                    "File Type": file_type,
                    "Size Category": size,
                    "Original File Size (KB)": round(orig_size_bytes / 1024, 2),
                    "Encrypted File Size (KB)": round(enc_size_bytes / 1024, 2),
                    "Encryption Time (ms)": round(enc_time * 1000, 4),
                    "Decryption Time (ms)": round(dec_time * 1000, 4),
                    "Enc Throughput (MB/s)": round(enc_throughput, 2),
                    "Dec Throughput (MB/s)": round(dec_throughput, 2),
                    "Avg Throughput (MB/s)": round(avg_throughput, 2),
                    "Integrity Verified": is_valid
                })
                
                print(f"[{file_type:5s} - {size:6s}] {algo:8s} | Enc: {enc_time*1000:7.2f} ms | Dec: {dec_time*1000:7.2f} ms | Throughput: {enc_throughput:7.2f} MB/s | Valid: {is_valid}")

    # Save to CSV
    csv_path = os.path.join(OUTPUT_DIR, "benchmark_results.csv")
    keys = results[0].keys()
    with open(csv_path, "w", newline="") as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)
        
    print(f"\nSaved raw benchmark results to {csv_path}")
    return results

def apply_dark_theme(fig, ax):
    # Dark theme matching the dashboard style
    bg_color = "#0f172a"  # Dark Slate Blue/Navy
    grid_color = "#1e293b"  # Darker Slate Grid
    text_color = "#94a3b8"  # Slate Gray Text
    
    fig.patch.set_facecolor(bg_color)
    ax.set_facecolor(bg_color)
    
    # Gridlines
    ax.grid(True, color=grid_color, linestyle="-", linewidth=0.5)
    ax.set_axisbelow(True)
    
    # Remove top/right spines, style left/bottom
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color(grid_color)
        
    # Text colors
    ax.tick_params(colors=text_color, which="both")
    ax.xaxis.label.set_color(text_color)
    ax.yaxis.label.set_color(text_color)
    if ax.title:
        ax.title.set_color("#f8fafc")

def generate_graphs(results):
    for file_type in FILE_TYPES:
        df_type = [r for r in results if r["File Type"] == file_type]
        
        # Color Palettes
        size_colors = {
            "Small": "#94a3b8",   # Slate Blue-Grey
            "Medium": "#3b82f6",  # Steel Blue
            "Large": "#ef4444"    # Warm Red
        }
        
        algo_colors = {
            "AES": "#10b981",       # Teal/Emerald
            "DES": "#64748b",       # Muted Gray
            "3DES": "#ef4444",      # Warm Red
            "Blowfish": "#3b82f6",  # Blue
            "ChaCha20": "#f59e0b"   # Amber Yellow
        }
        
        algo_markers = {
            "AES": "o",
            "DES": "s",
            "3DES": "^",
            "Blowfish": "D",
            "ChaCha20": "v"
        }
        
        # 1. Algorithm vs Encryption Time across sizes (Grouped Bar Chart)
        fig, ax = plt.subplots(figsize=(10, 6))
        apply_dark_theme(fig, ax)
        
        x = list(range(len(ALGORITHMS)))
        width = 0.25
        
        for i, size in enumerate(SIZES):
            vals = []
            for algo in ALGORITHMS:
                match = [r for r in df_type if r["Algorithm"] == algo and r["Size Category"] == size]
                vals.append(match[0]["Encryption Time (ms)"] if match else 0)
            
            offset = (i - 1) * width
            x_pos = [val + offset for val in x]
            ax.bar(x_pos, vals, width, label=size, color=size_colors[size])
            
        ax.set_title(f"{file_type} Files: Algorithm vs Encryption Time", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Algorithm", fontsize=12)
        ax.set_ylabel("Encryption Time (ms)", fontsize=12)
        ax.set_xticks(x)
        ax.set_xticklabels(ALGORITHMS)
        
        legend = ax.legend(facecolor="#0f172a", edgecolor="#1e293b", labelcolor="#f8fafc")
        legend.get_frame().set_alpha(0.8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, f"{file_type.lower()}_algo_vs_enc_time.png"), dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close()

        # 2. Algorithm vs Decryption Time (Grouped Bar Chart)
        fig, ax = plt.subplots(figsize=(10, 6))
        apply_dark_theme(fig, ax)
        
        for i, size in enumerate(SIZES):
            vals = []
            for algo in ALGORITHMS:
                match = [r for r in df_type if r["Algorithm"] == algo and r["Size Category"] == size]
                vals.append(match[0]["Decryption Time (ms)"] if match else 0)
            
            offset = (i - 1) * width
            x_pos = [val + offset for val in x]
            ax.bar(x_pos, vals, width, label=size, color=size_colors[size])
            
        ax.set_title(f"{file_type} Files: Algorithm vs Decryption Time", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Algorithm", fontsize=12)
        ax.set_ylabel("Decryption Time (ms)", fontsize=12)
        ax.set_xticks(x)
        ax.set_xticklabels(ALGORITHMS)
        
        legend = ax.legend(facecolor="#0f172a", edgecolor="#1e293b", labelcolor="#f8fafc")
        legend.get_frame().set_alpha(0.8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, f"{file_type.lower()}_algo_vs_dec_time.png"), dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close()

        # 3. File Size vs Encryption Time (Line plot)
        fig, ax = plt.subplots(figsize=(9, 6))
        apply_dark_theme(fig, ax)
        
        for algo in ALGORITHMS:
            sub = [r for r in df_type if r["Algorithm"] == algo]
            sub_sorted = sorted(sub, key=lambda x: x["Original File Size (KB)"])
            sizes_kb = [r["Original File Size (KB)"] for r in sub_sorted]
            times_ms = [r["Encryption Time (ms)"] for r in sub_sorted]
            ax.plot(sizes_kb, times_ms, marker=algo_markers[algo], label=algo, color=algo_colors[algo], linewidth=2)
            
        ax.set_title(f"{file_type} Files: File Size vs Encryption Time", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("File Size (KB)", fontsize=12)
        ax.set_ylabel("Encryption Time (ms)", fontsize=12)
        
        legend = ax.legend(facecolor="#0f172a", edgecolor="#1e293b", labelcolor="#f8fafc")
        legend.get_frame().set_alpha(0.8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, f"{file_type.lower()}_filesize_vs_enc_time.png"), dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close()

        # 4. File Size vs Decryption Time (Line plot)
        fig, ax = plt.subplots(figsize=(9, 6))
        apply_dark_theme(fig, ax)
        
        for algo in ALGORITHMS:
            sub = [r for r in df_type if r["Algorithm"] == algo]
            sub_sorted = sorted(sub, key=lambda x: x["Original File Size (KB)"])
            sizes_kb = [r["Original File Size (KB)"] for r in sub_sorted]
            times_ms = [r["Decryption Time (ms)"] for r in sub_sorted]
            ax.plot(sizes_kb, times_ms, marker=algo_markers[algo], label=algo, color=algo_colors[algo], linewidth=2)
            
        ax.set_title(f"{file_type} Files: File Size vs Decryption Time", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("File Size (KB)", fontsize=12)
        ax.set_ylabel("Decryption Time (ms)", fontsize=12)
        
        legend = ax.legend(facecolor="#0f172a", edgecolor="#1e293b", labelcolor="#f8fafc")
        legend.get_frame().set_alpha(0.8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, f"{file_type.lower()}_filesize_vs_dec_time.png"), dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close()

        # 5. Algorithm vs Encryption Throughput (Large Files)
        fig, ax = plt.subplots(figsize=(9, 6))
        apply_dark_theme(fig, ax)
        
        df_large = [r for r in df_type if r["Size Category"] == "Large"]
        algos = [r["Algorithm"] for r in df_large]
        throughputs = [r["Enc Throughput (MB/s)"] for r in df_large]
        
        ax.bar(algos, throughputs, color="#0d9488", alpha=0.9, width=0.5)
        
        ax.set_title(f"{file_type} Files (Large): Algorithm vs Encryption Throughput", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Algorithm", fontsize=12)
        ax.set_ylabel("Encryption Throughput (MB/s)", fontsize=12)
        
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, f"{file_type.lower()}_algo_vs_throughput.png"), dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close()

    print(f"Generated 15 comparative performance charts in {GRAPHS_DIR}")

if __name__ == "__main__":
    results = run_benchmarks()
    generate_graphs(results)

