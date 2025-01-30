from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# Function to pad plaintext to AES block size (16 bytes)
def pad(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    return padded_data

# Function to remove padding after decryption
def unpad(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# AES encryption function
def encrypt_AES(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padded_text = pad(plaintext)
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# AES decryption function
def decrypt_AES(key, ciphertext):
    raw_data = base64.b64decode(ciphertext)
    iv = raw_data[:16]  # Extract IV
    actual_ciphertext = raw_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_text = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return unpad(decrypted_padded_text)

# Main functionality
if __name__ == "__main__":
    # Generate a random 32-byte AES key (256-bit key)
    key = os.urandom(32)
    print(f"Generated AES Key (Base64): {base64.b64encode(key).decode('utf-8')}")

    # Message to encrypt
    plaintext = input("Enter a message to encrypt: ")
    
    # Encrypt the message
    encrypted = encrypt_AES(key, plaintext)
    print(f"Encrypted Message: {encrypted}")
    
    # Decrypt the message
    decrypted = decrypt_AES(key, encrypted)
    print(f"Decrypted Message: {decrypted}")
