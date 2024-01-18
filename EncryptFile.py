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

#Sign file function
def sign_file(user_id):
    with open("message.txt", "rb") as file:
        message = file.read()
    private_key, public_key = load_keys(user_id)

    # Hash message
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    file_hash = hasher.finalize()

    # Sign message
    my_signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Message signed")
    signed_file = file_hash + my_signature

    with open(f"signature_user{user_id}", "wb") as file:
        file.write(signed_file)

# Encrypt file based on user ID
def encrypt_file(user_id):
    private_key, public_key = load_keys(user_id)

    with open("message.txt", "rb") as file:
        message = file.read()

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(f"encryptedCiphertext_user.enc", "wb") as file:
        file.write(ciphertext)
        print(user_id)

    print("Message encrypted and sent to user:", {user_id})

# Example: User 2
user_id_1 = 1
user_id_2 = 2
sign_file(user_id_2)
encrypt_file(user_id_1)

