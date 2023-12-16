import crypto_backend
import encrypted_messenger
import json
import requests

r = open('Accounts/Tommy.txt', 'r')
tom = json.loads(r.readline())
tom = encrypted_messenger.KeyringEntry(crypto_backend.rsa_deserialize_private_key(tom['private_key']), tom['owner'], tom['id'])
r.close()

plaintext = b"hello"
(encrypted_session_key, nonce, ciphertext) = \
        crypto_backend.encrypt_message_with_aes_and_rsa(
                tom.public, plaintext)
        

# create the signature for this collection of attributes
fakeKey = crypto_backend.rsa_gen_keypair()
signature = crypto_backend.write_signature(fakeKey, encrypted_session_key+nonce+ciphertext)

# Package the encrypted session key, nonce, and ciphertext as a JSON
# object suitable for transmission to the recipient.
#
# N.B.: Even though we made a point to use UTF-8 instead of ASCII
# above for the message itself, it is safe to interpret the
# byte-string output of b64encode() as simple ASCII, because the
# base64 alphabet is entirely within the ASCII subset of Unicode (for
# which UTF-8 and ASCII are identical). I could've just as well
# specified 'utf-8' here, but this is a good teachable moment to
# explain the difference between the two...
packaged_msg = {
        'target': "Tommy",
        'sender': "TEST#1",
        'sessionkey': encrypted_messenger.b64encode(encrypted_session_key).decode('ascii'),
        'nonce': encrypted_messenger.b64encode(nonce).decode('ascii'),
        'ciphertext': encrypted_messenger.b64encode(ciphertext).decode('ascii'),
        'signature': encrypted_messenger.b64encode(signature).decode('ascii')
        }

jsonString = json.JSONEncoder().encode(packaged_msg)
requests.post("http://cs448lnx101.gcc.edu/posts/create", data = {'contents': 'bht-msg'+jsonString})