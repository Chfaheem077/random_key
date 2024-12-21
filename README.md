# random_key
from cryptography.fernet import Fernet

# Part 1: Caesar Cipher
def caesar_encrypt(plaintext, shift):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():  # Only shift letters
            shift_base = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Part 2: XOR Encryption
def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(char) ^ key) for char in text)

# Part 3: Robust Encryption with cryptography
def robust_encryption_decryption():
    # Generate a key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Example plaintext
    plaintext = "This is a secure message!"

    # Encrypt
    encrypted_text = cipher_suite.encrypt(plaintext.encode())
    print("\n[Robust] Encrypted text:", encrypted_text)

    # Decrypt
    decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
    print("[Robust] Decrypted text:", decrypted_text)

# Main Function
if __name__ == "__main__":
    # Caesar Cipher Example
    print("=== Caesar Cipher ===")
    plaintext = "HELLO, WORLD!"
    shift = 3
    encrypted_text = caesar_encrypt(plaintext, shift)
    print("Encrypted (Caesar):", encrypted_text)
    decrypted_text = caesar_decrypt(encrypted_text, shift)
    print("Decrypted (Caesar):", decrypted_text)

    # XOR Encryption Example
    print("\n=== XOR Encryption ===")
    text = "HELLO"
    key = 123  # Simple integer key
    encrypted_xor = xor_encrypt_decrypt(text, key)
    print("Encrypted (XOR):", encrypted_xor)
    decrypted_xor = xor_encrypt_decrypt(encrypted_xor, key)
    print("Decrypted (XOR):", decrypted_xor)

    # Robust Encryption Example
    print("\n=== Robust Encryption with cryptography ===")
    robust_encryption_decryption()
