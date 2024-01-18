# Import cryptography package
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate Public and Private keys
def generateKeys(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key to file with name "privatekey_user{id}.pem"
    with open(f"privatekey_user{user_id}.pem", "wb") as file:
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )

    # Save public key to file with name "publickey_user{id}.pem"
    with open(f"publickey_user{user_id}.pem", "wb") as file:
        file.write(pem)

    print(f"Keys for User {user_id} Generated")

# Generate keys for User 1
generateKeys(1)

# Generate keys for User 2
generateKeys(2)


