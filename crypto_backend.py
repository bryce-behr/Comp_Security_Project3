from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography.exceptions as cryptExceptions

import secrets # Use this for generating random byte strings (keys, etc.)
from time import perf_counter
from inspect import cleandoc # Cleans up indenting in multi-line strings (""")

baseUrl = 'http://cs448lnx101.gcc.edu/'
create = '/posts/create' # requires "contents" field
view = '/posts/view/'#append int id
viewRange = '/posts/get/'# append <int:from_id>/<int:to_id>, maximum range 1000
latest = '/posts/get/latest'
delete = '/posts/delete/<int:id>'

#
# Returns: An rsa.RSAPrivateKey object (which contains both the private key
#   and its corresponding public key; use .public_key() to obtain it).
#
RSA_KEY_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537
def rsa_gen_keypair():
    return rsa.generate_private_key(
            key_size = RSA_KEY_BITS,
            public_exponent = RSA_PUBLIC_EXPONENT
            )

#
# Argument: An rsa.RSAPrivateKey object
#
# Returns: An ASCII/UTF-8 string serialization of the private key using the
#   PKCS-8 format and PEM encoding. Does not encrypt the key for at-rest
#   storage.
#
def rsa_serialize_private_key(private_key):
    # Tommy
    if private_key == None:
        return
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
        ).decode("utf-8")

#
# Argument: A string containing an unencrypted RSA private key in PEM format.
#   Note that this also includes the matching public key (i.e., a PEM
#   "private key" serialization includes both halves of the keypair).
#
# Returns: An rsa.RSAPrivateKey object consisting of the deserialized key.
#
def rsa_deserialize_private_key(pem_privkey):
    # Tommy
    return serialization.load_pem_private_key(
        pem_privkey.encode(), 
        None
        )

#
# Argument: An rsa.RSAPublicKey object
#
# Returns: An ASCII/UTF-8 serialization of the public key using the
#   SubjectPublicKeyInfo format and PEM encoding.
#
def rsa_serialize_public_key(public_key):
    # Tommy
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

#
# Argument: A string containing an RSA public key in PEM format.
#
# Returns: An rsa.RSAPublicKey object consisting of the deserialized key.
#
def rsa_deserialize_public_key(pem_pubkey):
    # Tommy
    return serialization.load_pem_public_key(
        pem_pubkey.encode()
        )

#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message recipient.
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: The encrypted message (ciphertext), as a raw byte string.
#
def rsa_encrypt(public_key, plaintext):
    # Chris
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key of the
#       message recipient.
#   plaintext: The ciphertext message to be decrypted (as a raw byte string).
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def rsa_decrypt(private_key, ciphertext):
    # Chris
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext

#
# Encrypts a plaintext message using AES-256 in CTR (Counter) mode.
#
# Arguments:
#   key: A 256-bit (32-byte) secret key. This should either be randomly
#       generated, or derived from a password using a secure key derivation
#       function.
#   nonce: A 128-bit (16-byte) nonce to use with CTR mode. It is imperative
#       that this be randomly generated, and NEVER reused after being used
#       once to encrypt a single message. (This is because each time you
#       encrypt a message with the same nonce in CTR mode, the counter starts
#       fresh from 0 again, meaning the initial blocks will have been XORed
#       with the same keystream as the previous message - allowing the key to
#       be trivially recovered by comparing the two.)
#           (N.B.: Even though we are using AES-256, i.e. a key size of 256
#           bits, the nonce is still 128 bits, because the block size of AES
#           is always 128 bits. A longer key just increases the number of
#           rounds performed.)
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: The encrypted message (ciphertext), as a raw byte string.
#
def aes_encrypt(key, nonce, plaintext):
    # Bryce
    encryptor = Cipher(algorithms.AES256(key = key), modes.CTR(nonce = nonce)).encryptor()
    ciphertext = encryptor.update(data = plaintext) + encryptor.finalize()
    return ciphertext

#
# Decrypts a plaintext message using AES-256 in CTR (Counter) mode.
#
# Arguments:
#   key: A 256-bit (32-byte) secret key.
#   nonce: A 128-bit (16-byte) nonce to use with CTR mode.
#   ciphertext: The ciphertext message to be decrypted (as a raw byte string).
#
# No restrictions are placed on the values of key and nonce, but obviously,
# if they don't match the ones used to encrypt the message, the result will
# be gibberish.
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def aes_decrypt(key, nonce, ciphertext):
    # Bryce
    decryptor = Cipher(algorithms.AES256(key = key), modes.CTR(nonce = nonce)).decryptor()
    plaintext = decryptor.update(data = ciphertext) + decryptor.finalize()
    return plaintext

#
# Encrypts a plaintext message using AES-256-CTR using a randomly generated
# session key and nonce.
#
# Argument: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: A tuple containing the following elements:
#   session_key: The randomly-generated 256-bit session key used to encrypt
#       the message (as a raw byte string).
#   nonce: The randomly-generated 128-bit nonce used in the encryption (as a
#       raw byte string).
#   ciphertext: The encrypted message (as a raw byte string).
#
def aes_encrypt_with_random_session_key(plaintext):
    # Bryce
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    ciphertext = aes_encrypt(key = key, nonce = nonce, plaintext = plaintext)
    return (key, nonce, ciphertext)

#
# Encrypt a message using AES-256-CTR and a random session key, which in turn
# is encrypted with RSA so that it can be decrypted by the given public key.
#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message recipient.
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: A tuple containing the following elements:
#   encrypted_session_key: The randomly-generated AES session key, encrypted
#       using RSA with the given public key (as a raw byte string).
#   nonce: The randomly-generated nonce used in the AES-CTR encrpytion (as a
#       raw byte string).
#   ciphertext: The AES-256-CTR-encrypted message (as a raw byte string).
#
def encrypt_message_with_aes_and_rsa(public_key, plaintext):
    # Bryce
    aesMessage = aes_encrypt_with_random_session_key(plaintext)
    encrypted_session_key = rsa_encrypt(public_key = public_key, plaintext = aesMessage[0])
    return (encrypted_session_key, aesMessage[1], aesMessage[2])

#
# Decrypt a message that has been encrypted with AES-256-CTR, using an
# RSA-encrypted session key and an unencrypted nonce.
#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key that
#       will be used to decrypt the session key.
#   encrypted_session_key: The RSA-encrypted session key that will be used to
#       decrypt the actual message with AES-256-CTR (as a raw byte string).
#   nonce: The nonce that will be used to decrypt the message with
#       AES-256-CTR (as a raw byte string).
#   ciphertext: The AES-256-CTR-encrypted message (as a raw byte string).
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def decrypt_message_with_aes_and_rsa(
        private_key, encrypted_session_key, nonce, ciphertext):
    # Bryce
    decrypted_session_key = rsa_decrypt(private_key=private_key, ciphertext=encrypted_session_key)
    decrypted_message = aes_decrypt(key=decrypted_session_key, nonce=nonce, ciphertext=ciphertext)
    return decrypted_message

#
# Write a signature for an outgoing message using the provided RSA private key
#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key that
#       will be used to create a signature for the message.
#   message: The message as a raw byte string.
#
# Returns: the signature, as a raw byte string.
#
def write_signature(private_key, message):
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    return private_key.sign(message, pad, hashes.SHA256())

#
# Write a signature for an outgoing message using the provided RSA private key
#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message's alleged sender.
#   message: The message as a raw byte string.
#   signature: The signature to verify, as a raw byte string.
#
# Returns: whether the signature is correct, as a boolean value.
#
def verify_signature(public_key, message, signature):
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    try:
        public_key.verify(signature, message, pad, hashes.SHA256())
        return True
    except cryptExceptions.InvalidSignature:
        return False