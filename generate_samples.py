import os
from PIL import Image

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(SAMPLES_DIR, exist_ok=True)

def generate_text_file(filename, size_in_bytes):
    filepath = os.path.join(SAMPLES_DIR, filename)
    chunk = "Cryptography and Network Security Lab 2 - Symmetric Key Algorithms Benchmark.\n".encode("utf-8")
    repeats = (size_in_bytes // len(chunk)) + 1
    data = (chunk * repeats)[:size_in_bytes]
    with open(filepath, "wb") as f:
        f.write(data)
    print(f"Generated Text File: {filename} ({os.path.getsize(filepath) / 1024:.2f} KB)")
    return filepath

def generate_image_file(filename, width, height, target_min_size):
    filepath = os.path.join(SAMPLES_DIR, filename)
    # Generate colorful pattern image using Pillow
    img = Image.new("RGB", (width, height))
    pixels = img.load()
    for i in range(width):
        for j in range(height):
            pixels[i, j] = ((i * 5) % 256, (j * 7) % 256, (i + j) % 256)
    
    # Save as PNG
    img.save(filepath, format="PNG")
    
    # If size is smaller than target_min_size, pad metadata/bytes cleanly
    current_size = os.path.getsize(filepath)
    if current_size < target_min_size:
        pad_len = target_min_size - current_size
        with open(filepath, "ab") as f:
            f.write(os.urandom(pad_len))
            
    print(f"Generated Image File: {filename} ({os.path.getsize(filepath) / 1024:.2f} KB)")
    return filepath

def generate_video_file(filename, size_in_bytes):
    filepath = os.path.join(SAMPLES_DIR, filename)
    # Generate binary video container pattern (simulated MP4 binary stream)
    header = b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2avc1mp41"
    random_payload = os.urandom(size_in_bytes - len(header))
    with open(filepath, "wb") as f:
        f.write(header + random_payload)
    print(f"Generated Video File: {filename} ({os.path.getsize(filepath) / 1024:.2f} KB)")
    return filepath

def main():
    print("--- Generating Benchmark Sample Files ---")
    # Text Files
    generate_text_file("text_small.txt", 100 * 1024)       # 100 KB
    generate_text_file("text_medium.txt", 1 * 1024 * 1024)   # 1 MB
    generate_text_file("text_large.txt", 5 * 1024 * 1024)    # 5 MB

    # Image Files
    generate_image_file("image_small.png", 300, 300, 100 * 1024)      # ~100 KB
    generate_image_file("image_medium.png", 800, 800, 1 * 1024 * 1024)  # ~1 MB
    generate_image_file("image_large.png", 1500, 1500, 5 * 1024 * 1024) # ~5 MB

    # Video Files
    generate_video_file("video_small.mp4", 500 * 1024)      # 500 KB
    generate_video_file("video_medium.mp4", 2 * 1024 * 1024)  # 2 MB
    generate_video_file("video_large.mp4", 5 * 1024 * 1024)   # 5 MB
    print("--- Sample File Generation Complete ---")

if __name__ == "__main__":
    main()
