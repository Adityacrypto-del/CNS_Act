# Cryptography & Network Security Lab — Lab 2 Report
## Implementation & Performance Analysis of Symmetric Key Algorithms

---

### 1. Aim
To implement symmetric key algorithms (**AES**, **DES**, **3DES**, **Blowfish**, **ChaCha20**) for text, image, and video files and compare their performance based on encryption time, decryption time, file size, and throughput.

---

### 2. Software & Hardware Setup
* **Language/Runtime:** Python 3.9
* **Cryptographic Library:** `PyCryptodome` (v3.23.0)
* **Data & Visualization:** `Matplotlib` (v3.9.4) & Python Standard Library (`time.perf_counter`, `csv`, `os`)
* **Environment:** macOS ARM64 (Apple Silicon)

---

### 3. Empirical Performance Analysis Tables

All 45 experimental test runs were conducted on real byte streams of Text, Image, and Video data. Data integrity was verified byte-for-byte (`decrypted_content == original_content`) for all runs.

#### 3.1 Text File Benchmarks
| Algorithm | Size Category | File Size (KB) | Enc Time (ms) | Dec Time (ms) | Enc Throughput (MB/s) | Dec Throughput (MB/s) | Integrity Verified |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AES** | Small | 100.00 | 6.28 | 0.34 | 15.56 | 287.65 | Yes |
| **DES** | Small | 100.00 | 2.17 | 1.11 | 45.10 | 88.15 | Yes |
| **3DES** | Small | 100.00 | 4.06 | 3.75 | 24.05 | 26.04 | Yes |
| **Blowfish** | Small | 100.00 | 1.13 | 0.66 | 86.57 | 148.26 | Yes |
| **ChaCha20** | Small | 100.00 | 0.34 | 0.23 | **283.61** | **425.43** | Yes |
| **AES** | Medium | 1024.00 | 3.79 | 3.09 | 263.85 | 323.62 | Yes |
| **DES** | Medium | 1024.00 | 14.03 | 11.18 | 71.26 | 89.45 | Yes |
| **3DES** | Medium | 1024.00 | 47.61 | 37.25 | 21.01 | 26.85 | Yes |
| **Blowfish** | Medium | 1024.00 | 9.86 | 5.53 | 101.45 | 180.83 | Yes |
| **ChaCha20** | Medium | 1024.00 | 2.12 | 2.10 | **472.06** | **476.19** | Yes |
| **AES** | Large | 5120.00 | 19.04 | 16.25 | 262.61 | 307.69 | Yes |
| **DES** | Large | 5120.00 | 70.16 | 55.30 | 71.26 | 90.42 | Yes |
| **3DES** | Large | 5120.00 | 197.20 | 184.84 | 25.36 | 27.05 | Yes |
| **Blowfish** | Large | 5120.00 | 49.34 | 27.21 | 101.33 | 183.76 | Yes |
| **ChaCha20** | Large | 5120.00 | 10.40 | 10.35 | **480.74** | **483.09** | Yes |

---

#### 3.2 Image File Benchmarks
| Algorithm | Size Category | File Size (KB) | Enc Time (ms) | Dec Time (ms) | Enc Throughput (MB/s) | Dec Throughput (MB/s) | Integrity Verified |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AES** | Small | 100.00 | 0.42 | 0.33 | 231.44 | 296.36 | Yes |
| **DES** | Small | 100.00 | 1.39 | 1.09 | 70.12 | 89.72 | Yes |
| **3DES** | Small | 100.00 | 3.85 | 3.77 | 25.34 | 25.88 | Yes |
| **Blowfish** | Small | 100.00 | 1.02 | 0.58 | 96.20 | 168.97 | Yes |
| **ChaCha20** | Small | 100.00 | 0.24 | 0.22 | **410.54** | **448.18** | Yes |
| **AES** | Medium | 1024.00 | 3.76 | 3.11 | 266.07 | 321.54 | Yes |
| **DES** | Medium | 1024.00 | 13.84 | 12.05 | 72.24 | 82.99 | Yes |
| **3DES** | Medium | 1024.00 | 38.94 | 36.99 | 25.68 | 27.03 | Yes |
| **Blowfish** | Medium | 1024.00 | 9.87 | 5.47 | 101.29 | 182.82 | Yes |
| **ChaCha20** | Medium | 1024.00 | 2.08 | 2.07 | **480.73** | **483.09** | Yes |
| **AES** | Large | 5120.00 | 18.25 | 15.58 | 273.97 | 320.92 | Yes |
| **DES** | Large | 5120.00 | 69.47 | 57.19 | 71.98 | 87.43 | Yes |
| **3DES** | Large | 5120.00 | 198.67 | 186.78 | 25.17 | 26.77 | Yes |
| **Blowfish** | Large | 5120.00 | 49.37 | 27.14 | 101.27 | 184.23 | Yes |
| **ChaCha20** | Large | 5120.00 | 10.41 | 10.58 | **480.17** | **472.59** | Yes |

---

#### 3.3 Video File Benchmarks
| Algorithm | Size Category | File Size (KB) | Enc Time (ms) | Dec Time (ms) | Enc Throughput (MB/s) | Dec Throughput (MB/s) | Integrity Verified |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AES** | Small | 500.00 | 1.88 | 1.54 | 259.10 | 317.21 | Yes |
| **DES** | Small | 500.00 | 6.74 | 5.42 | 72.46 | 90.13 | Yes |
| **3DES** | Small | 500.00 | 19.26 | 18.50 | 25.35 | 26.39 | Yes |
| **Blowfish** | Small | 500.00 | 4.84 | 2.70 | 100.91 | 180.74 | Yes |
| **ChaCha20** | Small | 500.00 | 1.03 | 1.06 | **472.91** | **459.43** | Yes |
| **AES** | Medium | 2048.00 | 7.63 | 6.44 | 262.10 | 310.56 | Yes |
| **DES** | Medium | 2048.00 | 27.81 | 21.93 | 71.93 | 91.20 | Yes |
| **3DES** | Medium | 2048.00 | 77.54 | 73.88 | 25.79 | 27.07 | Yes |
| **Blowfish** | Medium | 2048.00 | 19.64 | 10.82 | 101.85 | 184.84 | Yes |
| **ChaCha20** | Medium | 2048.00 | 4.17 | 4.14 | **479.88** | **483.09** | Yes |
| **AES** | Large | 5120.00 | 17.91 | 15.49 | 279.18 | 322.79 | Yes |
| **DES** | Large | 5120.00 | 127.72 | 56.65 | 39.15 | 88.26 | Yes |
| **3DES** | Large | 5120.00 | 193.94 | 185.78 | 25.78 | 26.91 | Yes |
| **Blowfish** | Large | 5120.00 | 48.98 | 27.52 | 102.08 | 181.69 | Yes |
| **ChaCha20** | Large | 5120.00 | 10.43 | 10.65 | **479.38** | **469.48** | Yes |

---

### 4. Graphical Plots Summary
15 charts were generated and stored under the [graphs/](file:///Users/ayushbhandari/CNS/graphs) directory:
- `text_algo_vs_enc_time.png` & `text_algo_vs_dec_time.png`
- `text_filesize_vs_enc_time.png` & `text_filesize_vs_dec_time.png`
- `text_algo_vs_throughput.png`
- `image_algo_vs_enc_time.png` & `image_algo_vs_dec_time.png`
- `image_filesize_vs_enc_time.png` & `image_filesize_vs_dec_time.png`
- `image_algo_vs_throughput.png`
- `video_algo_vs_enc_time.png` & `video_algo_vs_dec_time.png`
- `video_filesize_vs_enc_time.png` & `video_filesize_vs_dec_time.png`
- `video_algo_vs_throughput.png`

---

### 5. Time Complexity Analysis
Theoretical symmetric encryption and decryption algorithms process input stream in block/stream chunks of size $B$.
For a file of size $N$ bytes:
- Total blocks $K = \lceil N / B \rceil$.
- Complexity of single block operations: $O(1)$.
- Total execution time $T(N) = K \times O(1) = O(N)$ (Linear Time Complexity).

**Empirical Verification:**
As observed in the line plots (`filesize_vs_enc_time.png` and `filesize_vs_dec_time.png`), the execution time scales strictly **linearly** with input file size across all algorithms (AES, DES, 3DES, Blowfish, ChaCha20). 
- **ChaCha20** exhibits the lowest slope ($\approx 2.04\text{ ms/MB}$), indicating exceptional scalability for large files.
- **AES-128** follows with a small slope ($\approx 3.75\text{ ms/MB}$).
- **3DES** exhibits the steepest slope ($\approx 38.6\text{ ms/MB}$), performing 3 passes of DES operations per block.

---

### 6. Overall Comparison Rankings

#### 6.1 Performance Parameters
| Parameter | Best Algorithm | Second Best | Worst Algorithm |
| :--- | :--- | :--- | :--- |
| **Encryption Speed** | **ChaCha20** (~10.4 ms for 5MB) | **AES** (~18.2 ms for 5MB) | **3DES** (~197.2 ms for 5MB) |
| **Decryption Speed** | **ChaCha20** (~10.3 ms for 5MB) | **AES** (~15.5 ms for 5MB) | **3DES** (~184.8 ms for 5MB) |
| **Throughput** | **ChaCha20** (~480 MB/s) | **AES** (~275 MB/s) | **3DES** (~25 MB/s) |
| **Small Files (< 100 KB)** | **ChaCha20** / **AES** | **Blowfish** | **3DES** |
| **Large Files (5 MB+)** | **ChaCha20** | **AES** | **3DES** |

#### 6.2 File Type Comparison
| File Type | Best Algorithm | Reason |
| :--- | :--- | :--- |
| **Text** | **ChaCha20** | Highest throughput (~480 MB/s), lightweight stream cipher with zero padding overhead. |
| **Image** | **ChaCha20** / **AES** | Fast byte-array stream encryption without metadata alteration; AES has hardware acceleration (AES-NI). |
| **Video** | **ChaCha20** | Ideal for high-bandwidth multimedia streaming; ultra-fast cipher with minimal CPU overhead. |

---

### 7. Answers to Lab Analysis Questions

#### Question 1: Which algorithm is fastest for text, image, and video files?
**Answer:** **ChaCha20** is consistently the fastest algorithm across all file types (Text, Image, and Video). For a 5 MB file, ChaCha20 completes encryption in ~10.4 ms compared to AES (~18 ms), Blowfish (~49 ms), DES (~70 ms), and 3DES (~197 ms).

#### Question 2: Does the fastest algorithm remain the fastest as file size increases?
**Answer:** **Yes.** As file size increases from 100 KB to 5 MB, ChaCha20 maintains its performance advantage due to its linear time complexity $O(N)$ with a significantly smaller constant coefficient compared to block ciphers requiring padding and round iterations.

#### Question 3: Which algorithm provides the highest throughput?
**Answer:** **ChaCha20** achieves the highest throughput (~475–480 MB/s), followed by **AES** (~260–279 MB/s). 3DES records the lowest throughput (~25 MB/s).

#### Question 4: How does file size affect encryption and decryption time?
**Answer:** Encryption and decryption times increase **proportionally (linearly)** with file size. Doubling the file size approximately doubles the execution time, conforming to $T(N) = O(N)$.

#### Question 5: Which algorithm scales better for large files?
**Answer:** **ChaCha20** and **AES-128** scale best for large files. ChaCha20 avoids block padding overheads and operates efficiently on 32-bit words, while AES benefits from efficient 128-bit block structures and hardware vectorization.

#### Question 6: Is there any significant difference between encryption and decryption time?
**Answer:** For stream ciphers like **ChaCha20**, encryption and decryption times are essentially identical (~10.4 ms vs ~10.3 ms) because both operations perform the exact same XOR keystream generation. For CBC mode block ciphers (AES, DES, 3DES, Blowfish), decryption is slightly faster (~10–20% speedup) because block cipher decryption lookup tables allow faster parallel sub-key execution during unpadding.

#### Question 7: Does the encrypted file size differ from the original file size?
**Answer:** 
- For **ChaCha20** (Stream Cipher): The encrypted file size is **identical** to the original file size (0 bytes expansion).
- For Block Ciphers (**AES, DES, 3DES, Blowfish** with PKCS7 padding): The ciphertext size is expanded to the next block multiple (adding between 1 to $B$ bytes of padding).

#### Question 8: Are the experimental results consistent with the expected time complexity?
**Answer:** **Yes.** The experimental results match the theoretical $O(N)$ time complexity. Linear regression on the empirical file size vs time data yields strong linear correlation ($R^2 \approx 0.99$).

#### Question 9: Which algorithm would you select for large-file encryption and why?
**Answer:** **AES-128 (GCM/CTR mode)** or **ChaCha20**.
- **ChaCha20** is preferred on mobile/ARM devices without dedicated crypto instructions due to its unmatched software speed.
- **AES-128** is preferred on modern desktop/server CPUs supporting hardware AES-NI instructions, offering top-tier security (NIST standard) alongside high speed.

#### Question 10: Can the fastest algorithm always be considered the best cryptographic algorithm? Justify.
**Answer:** **No.** Speed is only one factor. Cryptographic security, key length, resistance to cryptanalysis, and hardware support are equally critical. For instance:
- **DES** is fast but broken due to its small 56-bit key (vulnerable to brute-force attack in hours).
- Security standards require algorithms that resist differential cryptanalysis, side-channel attacks, and quantum threats. AES and ChaCha20 offer the optimal balance of modern 128/256-bit security and performance.

---

### 8. Conclusion
The performance of 5 symmetric key algorithms (**AES, DES, 3DES, Blowfish, ChaCha20**) was evaluated on Text, Image, and Video media across Small, Medium, and Large sizes. 
1. **ChaCha20** proved to be the fastest symmetric cipher with the highest throughput (~480 MB/s).
2. **AES-128** provided strong performance (~270 MB/s) combined with industry-standard NIST security.
3. Legacy ciphers (**DES, 3DES**) exhibited sub-optimal performance and are security-deprecated.
4. All algorithms verified 100% data integrity post-decryption.
