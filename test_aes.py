import base64
import os
import pytest
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from aes_encryption import encrypt_AES, decrypt_AES

# Generate a static AES key for testing
TEST_KEY = os.urandom(32)  # 256-bit AES key

@pytest.mark.parametrize("message", [
    "Hello, World!",
    "1234567890",
    "Test message with special chars! @#$%^&*()",
    "Multiline\nMessage\nHere"
])
def test_aes_encryption_decryption(message):
    """Test AES encryption and decryption for various inputs."""
    encrypted_message = encrypt_AES(TEST_KEY, message)

    # Ensure encryption output is Base64 encoded
    if not isinstance(encrypted_message, str):
        pytest.fail(f"Encryption output is not a string: {encrypted_message}")

    # Ensure decryption produces the original message
    decrypted_message = decrypt_AES(TEST_KEY, encrypted_message)
    if decrypted_message != message:
        pytest.fail(f"Decryption failed: expected '{message}', got '{decrypted_message}'")

def test_encryption_produces_different_output():
    """Ensure encryption produces different ciphertexts for different IVs."""
    message = "Hello, AES!"
    encrypted_1 = encrypt_AES(TEST_KEY, message)
    encrypted_2 = encrypt_AES(TEST_KEY, message)

    # Ensure two encryptions of the same message are different due to random IVs
    if encrypted_1 == encrypted_2:
        pytest.fail("Encryption with different IVs produced the same output!")

def test_decrypt_invalid_ciphertext():
    """Ensure decryption fails for invalid ciphertexts."""
    with pytest.raises(Exception) as excinfo:
        decrypt_AES(TEST_KEY, "InvalidCiphertext12345")
    if "invalid" not in str(excinfo.value).lower():
        pytest.fail(f"Unexpected exception message: {excinfo.value}")
