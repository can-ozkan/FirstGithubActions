from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to pad plaintext to be a multiple of AES block size (16 bytes)

def pad(text):

    while len(text) % 16 != 0:

        text += " "

    return text



# AES encryption function

def encrypt_AES(key, plaintext):

    cipher = AES.new(key, AES.MODE_ECB)

    padded_text = pad(plaintext)

    ciphertext = cipher.encrypt(padded_text.encode('utf-8'))

    return base64.b64encode(ciphertext).decode('utf-8')



# AES decryption function

def decrypt_AES(key, ciphertext):

    cipher = AES.new(key, AES.MODE_ECB)

    encrypted_data = base64.b64decode(ciphertext)

    decrypted_text = cipher.decrypt(encrypted_data).decode('utf-8').strip()

    return decrypted_text



# Main functionality

if __name__ == "__main__":
    # Generate a random 16-byte AES key
    key = get_random_bytes(16)
    print(f"Generated AES Key: {base64.b64encode(key).decode('utf-8')}")
    print(f"Generated AES Key: {key}")

    # Message to encrypt
    plaintext = input("Enter a message to encrypt: ")

    # Encrypt the message
    encrypted = encrypt_AES(key, plaintext)
    print(f"Encrypted Message: {encrypted}")

    # Decrypt the message
    decrypted = decrypt_AES(key, encrypted)
    print(f"Decrypted Message: {decrypted}")
