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
    # Load the public key from a PEM file
    with open(f"publickey_user{user_id}.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    return private_key, public_key

# Sign a file with a digital signature using a user's private key
def sign_file(user_id):
    with open("message.txt", "rb") as file:
        message = file.read()
    # Load the private and public keys
    private_key, public_key = load_keys(user_id)

    # Hash the message using SHA256
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    file_hash = hasher.finalize()

    # Sign the hashed message
    my_signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Message signed")
    # Combine the original hash and the signature
    signed_file = file_hash + my_signature

    # Write the signed message to a file
    with open(f"signature_user{user_id}", "wb") as file:
        file.write(signed_file)

# Encrypt a file using a user's public key
def encrypt_file(user_id):
    # Load the private and public keys
    private_key, public_key = load_keys(user_id)

    # Read the content of the message file
    with open("message.txt", "rb") as file:
        message = file.read()

    # Encrypt the message using the user's public key
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted message to a file
    with open(f"encryptedCiphertext_user.enc", "wb") as file:
        file.write(ciphertext)
        print(user_id)

    print("Message encrypted and sent to user:", {user_id})

# Example: User 2 signs a file and encrypts with user 1 public key
user_id_1 = 1
user_id_2 = 2
sign_file(user_id_2)
encrypt_file(user_id_1)

