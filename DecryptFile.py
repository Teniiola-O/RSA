from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Load the private and public keys for a specific user
def load_keys(user_id):
    # Load the private key from a PEM file
    with open(f"privatekey_user{user_id}.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    # Load the private key from a PEM file
    with open(f"publickey_user{user_id}.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    return private_key, public_key

# Verify the signature of a message for a specific user
def verify_signature(user_id):
    # Load the private and public keys
    private_key, public_key = load_keys(user_id)
    # Read the signed message from a file
    with open(f"signature_user{user_id}", "rb") as f:
        signed_message = f.read()

    # Extract the message and signature from the signed message
    message = signed_message[:32]
    signature = signed_message[32:]
    
    # Verify the signature using the public key
    verifier = public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Print the verification result
    try:
        verifier
        print(f"Signature verification for User {user_id} successful. Data integrity verified.")
    except Exception as e:
        print(f"Signature verification for User {user_id} failed: {e}")
        return None

# Decrypt an encrypted file using the private key of a specific user
def decrypt_file(user_id):
    # Load the private key
    private_key, public_key = load_keys(user_id)
    # Read the ciphertext from an encrypted file
    with open(f"encryptedCiphertext_user.enc", "rb") as file:
        ciphertext = file.read()

    # Decrypt the ciphertext using the private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Write the decrypted plaintext to a file
    with open(f"decryptedPlaintext_user.txt", "wb") as file:
        file.write(plaintext)
    print(f"Message Decrypted for User {user_id}")

# Example: Verify the signature for User 2 and decrypt the file for User 1
user_id_1 = 1
user_id_2 = 2
verify_signature(user_id_2)
decrypt_file(user_id_1)


