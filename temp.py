import crypto_backend
import secrets
keypair = crypto_backend.rsa_gen_keypair()
serial = crypto_backend.rsa_serialize_private_key(keypair)
print(serial)
# print(crypto_backend.rsa_deserialize_private_key(serial) == keypair)
# serial = crypto_backend.rsa_serialize_public_key(keypair.public_key())
# print(serial)
# print(crypto_backend.rsa_deserialize_public_key(serial) == keypair.public_key())

# aaa = secrets.randbits(k = 256)
# bbb = str(aaa).encode()
# print(aaa)
# print(bbb)
# print(bbb.decode() == aaa)

# temp = crypto_backend.aes_encrypt_with_random_session_key(b"plaintext")
# print(temp[0]+b"---------"+temp[1]+b"---------"+temp[2])