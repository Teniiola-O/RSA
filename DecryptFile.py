from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Load the keys
def load_keys(user_id):
    with open(f"privatekey_user{user_id}.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(f"publickey_user{user_id}.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    return private_key, public_key

# Verify signature
def verify_signature(user_id):
    private_key, public_key = load_keys(user_id)
    with open(f"signature_user{user_id}", "rb") as f:
        signed_message = f.read()

    message = signed_message[:32]
    signature = signed_message[32:]
    verifier = public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    try:
        verifier
        print(f"Signature verification for User {user_id} successful. Data integrity verified.")
    except Exception as e:
        print(f"Signature verification for User {user_id} failed: {e}")
        return None

# Decrypt file
def decrypt_file(user_id):
    private_key, public_key = load_keys(user_id)
    with open(f"encryptedCiphertext_user.enc", "rb") as file:
        ciphertext = file.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(f"decryptedPlaintext_user.txt", "wb") as file:
        file.write(plaintext)
    print(f"Message Decrypted for User {user_id}")

# Example: Verify the signature for User 2 and decrypt the file for User 1
user_id_1 = 1
user_id_2 = 2
verify_signature(user_id_2)
decrypt_file(user_id_1)


