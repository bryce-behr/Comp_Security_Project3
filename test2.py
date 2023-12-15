import crypto_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

privKey = crypto_backend.rsa_gen_keypair()
(encrypted_session_key, nonce, ciphertext) = crypto_backend.encrypt_message_with_aes_and_rsa(privKey.public_key(), b"plaintext")
#print("key: ", encrypted_session_key,"nonce: ", nonce, "text: ", ciphertext)

signature = privKey.sign(
    encrypted_session_key+nonce+ciphertext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

privKey.public_key().verify(
    signature,
    encrypted_session_key+nonce+ciphertext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)