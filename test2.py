import crypto_backend
import encrypted_messenger
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

privKey = crypto_backend.rsa_gen_keypair()
(encrypted_session_key, nonce, ciphertext) = crypto_backend.encrypt_message_with_aes_and_rsa(privKey.public_key(), b"plaintext")
#print("key: ", encrypted_session_key,"nonce: ", nonce, "text: ", ciphertext)

signature = crypto_backend.write_signature(privKey, encrypted_session_key+nonce+ciphertext)

signature = encrypted_messenger.b64encode(signature).decode('ascii')
encrypted_session_key = encrypted_messenger.b64encode(encrypted_session_key).decode('ascii')
nonce = encrypted_messenger.b64encode(nonce).decode('ascii')
ciphertext = encrypted_messenger.b64encode(ciphertext).decode('ascii')

signature = encrypted_messenger.b64decode(signature)
encrypted_session_key = encrypted_messenger.b64decode(encrypted_session_key)
nonce = encrypted_messenger.b64decode(nonce)
ciphertext = encrypted_messenger.b64decode(ciphertext)



print(crypto_backend.verify_signature(privKey.public_key(), encrypted_session_key+nonce+ciphertext, signature))