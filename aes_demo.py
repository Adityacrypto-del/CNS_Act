from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b"0123456789abcdef"
iv = b"abcdef9876543210"
plaintext = b"Hello AES Algorithm"

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print("Plaintext:", plaintext.decode())
print("Encrypted data (hex):", ciphertext.hex())

decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)

print("Decrypted data:", decrypted.decode())
