#     max = json.loads(requests.get(baseUrl+latest).text)['posts'][0]['id']
#     min = max-999
#     if min <= 1 : min = 1

#     jsonized = json.loads(requests.get(baseUrl+viewRange+str(min)+'/'+str(max)).text)
#     posts = jsonized['posts']        

#     for post in posts:
#         if(post['contents'][0:7] == "bht-app"):
#             jsonizedPost =  json.loads(post['contents'][7:])
#             # try:
#             print(jsonizedPost['pubkey'])
#             add_otherAccounts_entry(KeyringEntry(key = crypto_backend.rsa_deserialize_public_key(jsonizedPost['pubkey']), owner = jsonizedPost['owner']))
#             # except:
#                 # continue
#     # for post in posts:
#     #     if(post['contents'][0:7] == "bht-app"):
#     #         print(str(post['id']) + 'deleted')
#     #         json.loads(requests.post(baseUrl+delete+str(post['id']), data = {'hash' : hashlib.sha1(post['contents'].encode('utf-8')).hexdigest()}).text)




# started = False
# p1 = Process(target=check_new_users)
# p1.start()



# p1.kill()
# jsonized = json.loads(requests.get(baseUrl+viewRange+'400/430').text)
# posts = jsonized['posts']        

# for post in posts:
#     if(post['contents'][0:7] == "bht-"):
#         print(str(post['id']) + 'deleted')
#         json.loads(requests.post(baseUrl+delete+str(post['id']), data = {'hash' : hashlib.sha1(post['contents'].encode('utf-8')).hexdigest()}).text)




# def add_otherAccounts_entry(entry):
#     otherAccounts.append(entry)

#     window["_targetList"].update(values = compute_otherAccountList(),
#                               set_to_index = len(otherAccounts) - 1)
#     window["_targetToUseLabel"].update(f"Target to use ({len(otherAccounts)} loaded):")


# otherAccountsList = []

# def compute_otherAccountList():
#     otherAccountsList = []
#     for key in otherAccounts:
#         entry = key.owner

#         if key.private:
#             entry += " (public + private)"
#         else:
#             entry += " (public only)"

#         otherAccountsList.append(entry)

#     return otherAccountsList



            # if(event == "_keylist"):
            #     temp = []
            #     for target in targets:
            #         temp.append(target)
            #     targetIndex = 0
            #     selected_idx = window["_keylist"].widget.current()
            #     if selected_idx in range(0, len(keyring)):
            #         account_name = keyring[selected_idx].owner
            #         selected_tgt = window["_targetList"].widget.current()
            #         targetIndex = selected_tgt
            #         if selected_tgt in range(0, len(targets)):
            #             target_name = targets[selected_tgt].owner
            #             if account_name == target_name:    
            #                 temp.remove(targets[selected_tgt])
            #                 targetIndex = max(targetIndex, 0)  # Setting lower bound
            #                 targetIndex = min(targetIndex, temp.length - 1)

            #     window["_targetList"].update(values = compute_targetlist(targets=temp), set_to_index = targetIndex)
            #     # window["_targetList"]



        # elif event == "Import Key":
        #     # We will interpret the notepad contents as a JSON dictionary that we
        #     # expect to contain the following entries:
        #     #   * 'owner': The name of the key's owner; AND
        #     #   * 'privkey': A PEM serialization of a combined public/private
        #     #       keypair; OR
        #     #   * 'pubkey': A PEM serialization of a public key by itself
        #     #
        #     # Normally, only one of 'privkey' or 'pubkey' will be present. If
        #     # both are present, we will use 'privkey' and ignore 'pubkey'.
        #     try:
        #         packaged_public_key = json.JSONDecoder().decode(values["_notepad"])
        #     except json.decoder.JSONDecodeError:
        #         sg.popup("Error: Couldn't parse input as valid JSON.",
        #                 title = "Error Reading Key")
        #         continue

        #     # If the 'owner' field is missing, display an error and cancel.
        #     if 'owner' not in packaged_public_key:
        #         sg.popup("Missing field: key owner not specified!",
        #                 title = "Error Reading Key")
        #         continue

        #     # If either the 'privkey' or 'pubkey' field is present, process it
        #     # accordingly. If neither is present, display an error and cancel.
        #     try:
        #         if 'privkey' in packaged_public_key:
        #             key = crypto_backend.rsa_deserialize_private_key(
        #                     packaged_public_key['privkey'])
        #         elif 'pubkey' in packaged_public_key:
        #             key = crypto_backend.rsa_deserialize_public_key(
        #                     packaged_public_key['pubkey'])
        #         else:
        #             sg.popup("No public or private key found in input!",
        #                     title = "Error Reading Key")
        #             continue
        #     except ValueError as e:
        #         # The cryptography library threw an error trying to deserialize
        #         # the key. Report it and cancel.
        #         sg.popup_scrolled(e, title = "Error Reading Key")
        #         continue

        #     # Add the key to the keyring. add_keyring_entry() will automatically
        #     # update the drop-down list of all the keys that have been loaded
        #     # into the app (and the "# loaded" label next to it).
        #     entry = KeyringEntry(key, packaged_public_key['owner'])
        #     add_keyring_entry(entry)

        # elif event == "Export Private Key":
        #     # Get the index of the currently-selected key (see comment above
        #     # under "Encrypt" case).
        #     selected_idx = window["_keylist"].widget.current()

        #     if selected_idx not in range(0, len(keyring)):
        #         # The index is out of bounds. This can happen if no keys have
        #         # been added to the keyring yet (the call to current() will
        #         # return -1 if there are no items in the Combo), or (potentially)
        #         # in case of a program bug.
        #         sg.popup("No key selected!")
        #         continue

        #     # Serialize the selected key to PEM format. We will serialize the
        #     # entire keypair (public + private) as a "PRIVATE KEY" block which
        #     # can be used to re-import the full keypair.
        #     keyring_entry = keyring[selected_idx]
        #     if not keyring_entry.private:
        #         sg.popup("We only have the public component of that key.\n"
        #                 "Try \"Export Public Key\" to export just the "
        #                 "public component.", title = "Error Exporting Key")
        #         continue # Stop processing this event

        #     key_pem = crypto_backend.rsa_serialize_private_key(
        #             keyring_entry.private)

        #     # Package the key in a JSON object that includes the associated owner
        #     # name.
        #     packaged_public_key = {
        #             'owner': keyring_entry.owner,
        #             'privkey': key_pem
        #             }
        #     jsonified_public = json.JSONEncoder().encode(packaged_public_key)

        #     # Display the JSON in the notepad area.
        #     window["_notepad"].update(jsonified_public)

        # elif event == "Export Public Key":
        #     # Get the index of the currently-selected key (see comment above
        #     # under "Encrypt" case).
        #     selected_idx = window["_keylist"].widget.current()

        #     if selected_idx not in range(0, len(keyring)):
        #         # The index is out of bounds. This can happen if no keys have
        #         # been added to the keyring yet (the call to current() will
        #         # return -1 if there are no items in the Combo), or (potentially)
        #         # in case of a program bug.
        #         sg.popup("No key selected!")
        #         continue

        #     # Serialize the selected key's public component to PEM format.
        #     keyring_entry = keyring[selected_idx]
        #     key_pem = crypto_backend.rsa_serialize_public_key(
        #             keyring_entry.public)

        #     # Package the key in a JSON object that includes the associated owner
        #     # name.
        #     packaged_public_key = {
        #             'owner': keyring_entry.owner,
        #             'pubkey': key_pem
        #             }
        #     jsonified_public = json.JSONEncoder().encode(packaged_public_key)

        #     # Display the JSON in the notepad area.
        #     window["_notepad"].update(jsonified_public)



        # elif event == "Decrypt":
        #     # Get the index of the currently-selected key (see comment above
        #     # under "Encrypt" case).
        #     selected_idx = window["_keylist"].widget.current()

        #     if selected_idx not in range(0, len(keyring)):
        #         # The index is out of bounds. This can happen if no keys have
        #         # been added to the keyring yet (the call to current() will
        #         # return -1 if there are no items in the Combo), or (potentially)
        #         # in case of a program bug.
        #         sg.popup("No key selected!")
        #         continue

        #     # Get the private component of the selected recipient's keypair.
        #     if not keyring[selected_idx].private:
        #         sg.popup("We only have the public component of that key.\n"
        #                 "We can send messages *to* it, but not decrypt "
        #                 "messages encrypted for it.", title = "Cannot Decrypt")
        #         continue # Stop processing this event
        #     private_key = keyring[selected_idx].private

        #     # Unpackage the notepad area's contents as a JSON object
        #     # encapsulating the encrypted session key, nonce, and ciphertext.
        #     try:
        #         packaged_msg = json.JSONDecoder().decode(values["_notepad"])
        #     except json.decoder.JSONDecodeError:
        #         sg.popup("Error: Couldn't parse input as valid JSON.",
        #                 title = "Error Decrypting Message")
        #         continue

        #     # The session key, nonce, and ciphertext are encoded in the JSON as
        #     # base64 strings; decode them to recover the original byte strings.
        #     try:
        #         # N.B.: The b64decode() function doesn't require us to explicitly
        #         # convert the string inputs into raw byte strings. Unlike
        #         # b64encode(), it will automatically interpret an input string as
        #         # ASCII (which is enough for the full base64 alphabet).
        #         encrypted_session_key = b64decode(
        #                 packaged_msg['sessionkey'], validate = True)
        #         nonce = b64decode(packaged_msg['nonce'], validate = True)
        #         ciphertext = b64decode(packaged_msg['ciphertext'], validate = True)
        #     except binascii.Error:
        #         # This will only trigger if characters other than A-Z, a-z, 0-9,
        #         # +, or / (or = for length padding at the end) are found in the
        #         # input. Corruptions that produce a legitimate base64 character
        #         # cannot be detected and will silently change the data.
        #         #
        #         # (In the next project, we will learn how to use authenticated
        #         # encryption to detect corruption! 🙂)
        #         #
        #         # Note that we could have set validate = False (the default) in
        #         # the b64decode() calls above; but this will silently skip the
        #         # bad characters, which would render the entire rest of the
        #         # message unreadable (since the ciphertext would become
        #         # desynchronized with the keystream).
        #         sg.popup("Error: Invalid characters found in base64 input.",
        #                 title = "Error Decrypting Message")
        #         continue

        #     # Decrypt the session key using RSA, and then the message using AES
        #     # with the session key and nonce.
        #     try:
        #         plaintext = crypto_backend.decrypt_message_with_aes_and_rsa(
        #                 private_key, encrypted_session_key, nonce, ciphertext)
        #     except ValueError as e:
        #         # The cryptography library threw an error trying to decrypt the
        #         # message. Report it and cancel.
        #         sg.popup_scrolled(e, title = "Error Decrypting Message")
        #         continue

        #     # Display the decrypted message in the notepad area.
        #     #
        #     # N.B.: The output of the decryption function is a raw byte string,
        #     # so we need to convert this back to a UTF-8 string. (We used UTF-8
        #     # encoding for the input when originally encrypting the message, so
        #     # this should allow non-ASCII characters to come out the other end
        #     # unscathed.)
        #     window["_notepad"].update(plaintext.decode('utf-8'))