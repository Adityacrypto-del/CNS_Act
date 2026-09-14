import os
from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20
from Crypto.Util.Padding import pad, unpad

# Fixed Keys & IVs for standard benchmarking
KEYS = {
    "AES": os.urandom(16),       # AES-128 bit key
    "DES": os.urandom(8),        # 64-bit key
    "3DES": DES3.adjust_key_parity(os.urandom(24)), # 192-bit key
    "Blowfish": os.urandom(16),  # 128-bit key
    "ChaCha20": os.urandom(32),  # 256-bit key
}

def get_iv_or_nonce(algo):
    if algo == "AES":
        return os.urandom(16)
    elif algo in ["DES", "3DES", "Blowfish"]:
        return os.urandom(8)
    elif algo == "ChaCha20":
        return os.urandom(12) # 96-bit nonce
    return None

def encrypt_data(algo, plaintext, key, iv_or_nonce):
    """Encrypts plaintext bytes using the specified algorithm."""
    if algo == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv_or_nonce)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    elif algo == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv_or_nonce)
        ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    elif algo == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv_or_nonce)
        ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    elif algo == "Blowfish":
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv_or_nonce)
        ciphertext = cipher.encrypt(pad(plaintext, Blowfish.block_size))
    elif algo == "ChaCha20":
        cipher = ChaCha20.new(key=key, nonce=iv_or_nonce)
        ciphertext = cipher.encrypt(plaintext)
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")
    return ciphertext

def decrypt_data(algo, ciphertext, key, iv_or_nonce):
    """Decrypts ciphertext bytes using the specified algorithm."""
    if algo == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv_or_nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif algo == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv_or_nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    elif algo == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv_or_nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif algo == "Blowfish":
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv_or_nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    elif algo == "ChaCha20":
        cipher = ChaCha20.new(key=key, nonce=iv_or_nonce)
        plaintext = cipher.decrypt(ciphertext)
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")
    return plaintext
