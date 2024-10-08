#!/usr/bin/env python

import binascii
import threading
import requests
import PySimpleGUI as sg
import json
from base64 import b64encode, b64decode

import crypto_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

import requests

import hashlib

import os

from multiprocessing import Process
import time

#
# A class that represents an RSA keypair associated with the name of its
# owner.
#
# Properties:
#   private: The private portion of the keypair.
#       Can be None if we only have the public key.
#
#   public: The public portion of the keypair.
#
#   owner: A string indicating the owner of the key.
#
class KeyringEntry:
    #
    # You can pass either an RSAPrivateKey or RSAPublicKey for "key".
    #
    # If it's a private key, we will extract the corresponding public key and
    # set both properties. Otherwise, we will set only the public key.
    #
    def __init__(self, key, owner, postid=-1):
        self.owner = owner
        self.postid = postid

        if isinstance(key, RSAPrivateKey):
            self.private = key
            self.public = key.public_key()
        elif isinstance(key, RSAPublicKey):
            self.public = key
            self.private = None
        else:
            raise Exception("Unrecognized key type!")
        
    def toJSON(self):
        dictionary = {
            'owner':self.owner,
            'postid':self.postid,
            'private':crypto_backend.rsa_serialize_private_key(self.private),
            'public':crypto_backend.rsa_serialize_public_key(self.public)
        }
        return dictionary

def JSONKeyring(json):
    if json['private'] == None:
        return KeyringEntry(crypto_backend.rsa_deserialize_public_key(json['public']), json['owner'], json['postid'])
    return KeyringEntry(crypto_backend.rsa_deserialize_private_key(json['private']), json['owner'], json['postid'])

#
# Return a list of human-readable drop-down-list entries for all the keys in
# "keyring". Each entry lists the owner's name and whether we have the full
# keypair or just the public key. Examples:
#
#       Jimothy Ronsberg (public + private)
#       Barry Millham (public only)
#
def compute_keylist():
    keylist = []
    for key in keyring:
        entry = key.owner

        # if key.private:
        #     entry += " (public + private)"
        # else:
        #     entry += " (public only)"

        keylist.append(entry)

    return keylist

def keylist_contains(owner):
    for key in keyring:
        if owner == key.owner:
            return True
    return False

def compute_targetlist(targets):
    targetlist = []
    for target in targets:
        entry = target.owner
        targetlist.append(entry)

    return targetlist

def targetlist_contains(owner):
    for target in targets:
        if owner == target.owner:
            return True
    return False

#
# Add a key entry to "keyring", and update the drop-down list of all the
# keys that have been loaded into the app.
#
# Argument: A KeyringEntry object.
#
def add_keyring_entry(entry):
    keyring.append(entry)

    window["_keylist"].update(values = compute_keylist(),
                              set_to_index = len(keyring) - 1)
    
def add_target(target):
    targets.append(target)
    window["_targetList"].update(values = compute_targetlist(targets))

def updateMessages(account, target):
    tempString = ""
    if account.owner != target.owner:
        for message in messages:
            if message['sender'] == account.owner and message['target'] == target.owner:
                text = message['plaintext']
                tempString += ('\t\t\t\t['+message['sender']+"] "+text)+'\n'
            if message['target'] == account.owner and message['sender'] == target.owner:
                if 'plaintext' in message:
                    text = message['plaintext']
                    tempString += "["+message['sender']+"] "+text+'\n'
                    continue
                key = b64decode(message['sessionkey'], validate=True)
                nonce = b64decode(message['nonce'], validate=True)
                text = b64decode(message['ciphertext'], validate=True)
                signature = b64decode(message['signature'], validate=True)
                m = key+nonce+text
                if not crypto_backend.verify_signature(target.public, m, signature):
                    continue #this message was faked
                if 'plaintext' in message:
                    text = message['plaintext']
                else:
                    text = decryptMessage(message, account.private).decode()
                tempString += "["+message['sender']+"] "+text+'\n'
    return tempString


######################################################################
# Main event loop for window
######################################################################
def MainLoop():
    while True:
        event, values = window.read()

        # Uncomment for debugging
        # print(f"Event: {event}\nValues:{values}\n")

        if event == sg.WIN_CLOSED:
            break

        elif event == "Clear":
            window["_notepad"].update("")

        elif event == "Send":
            # PySimpleGUI unfortunately doesn't provide a "clean" way to get the
            # numeric index of the currently-selected element in a Combo
            # (drop-down box); all it can do is give us the currently-displayed
            # string, which can be ambiguous if there are multiple elements with
            # the same text. We therefore use the current() method on the
            # underlying Tk widget. (This might not work properly if you try
            # porting this to a different PySimpleGUI backend.)
            selected_idx = window["_keylist"].widget.current()

            if selected_idx not in range(0, len(keyring)):
                # The index is out of bounds. This can happen if no keys have
                # been added to the keyring yet (the call to current() will
                # return -1 if there are no items in the Combo), or (potentially)
                # in case of a program bug.
                sg.popup("No account selected!")
                continue

            # Get the private component of the selected account's keypair.
            account_key = keyring[selected_idx].private
            account_name = keyring[selected_idx].owner
            account_post = keyring[selected_idx].postid
            
            #check to make sure that the public key is still posted on the pastebin
            if account_post != -1:
                if requests.get(baseUrl+view+str(account_post)).json()['error'] == True:
                    # Serialize the selected key's public component to PEM format.
                    pem = crypto_backend.rsa_serialize_public_key(
                            keyring[selected_idx].public)
                    packaged_public_key = {
                            'owner': account_name,
                            'pubkey': pem
                            }
                    jsonified_public = json.JSONEncoder().encode(packaged_public_key)

                    post = json.loads(requests.post(baseUrl+create, data = {'contents': prefix+jsonified_public}).text)
                    
                    packaged_private_key = {
                        'id': post['id'],
                        'owner': account_name,
                        'private_key': crypto_backend.rsa_serialize_private_key(account_key)
                    }
                    jsonified_private = json.JSONEncoder().encode(packaged_private_key)
                    
                    file = open('Accounts\\'+account_name+'.txt', 'w')
                    file.write(jsonified_private)
                    file.close()
                    
                    keyring[selected_idx].postid = post['id']
                    
                    

                    
            selected_idx = window["_keylist"].widget.current()
            selected_tgt = window["_targetList"].widget.current()
            temp = []
            for target in targets:
                if target.owner != keyring[selected_idx].owner:
                    temp.append(target)
            # window['_targetList'].update(values = compute_targetlist(temp), set_to_index = min(selected_tgt, len(temp)-1))
            # if selected_tgt in range(0, len(targets)):
            #     tempString = updateMessages(keyring[selected_idx], temp[min(selected_tgt, len(temp)-1)])
            #     window["_notepad"].update(tempString)            

            # see above, repeated for targetlist
            # selected_tgt = window["_targetList"].widget.current()
            # if selected_tgt not in range(0, len(targets)):
            #     sg.popup("No target selected!")
            #     continue
            target_key = temp[selected_tgt].public
            target_name = temp[selected_tgt].owner

            # Encrypt the contents of the notepad area with a randomly-generated
            # AES session key (which in turn is encrypted with RSA so it can be
            # decrypted by the recipient's private key).
            #
            # N.B.: We must encode the notepad contents as a raw byte string
            # (vs. a regular string), because only raw bytes are suitable for
            # input to the encryption functions. We use UTF-8 (Unicode) encoding
            # here to allow non-ASCII characters in messages.
            plaintext = values["_messageBox"].encode('utf-8')
            (encrypted_session_key, nonce, ciphertext) = \
                    crypto_backend.encrypt_message_with_aes_and_rsa(
                            target_key, plaintext)
            # create the signature for this collection of attributes
            signature = crypto_backend.write_signature(account_key, encrypted_session_key+nonce+ciphertext)

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
                    'target': target_name,
                    'sender': account_name,
                    'sessionkey': b64encode(encrypted_session_key).decode('ascii'),
                    'nonce': b64encode(nonce).decode('ascii'),
                    'ciphertext': b64encode(ciphertext).decode('ascii'),
                    'signature': b64encode(signature).decode('ascii')
                    }
            
            jsonString = json.JSONEncoder().encode(packaged_msg)
            requests.post(baseUrl+create, data = {'contents': 'bht-msg'+jsonString})

            packaged_msg['plaintext'] = plaintext.decode()
            packaged_msg.pop('ciphertext')
            packaged_msg.pop('signature')
            packaged_msg.pop('nonce')
            packaged_msg.pop('sessionkey')
            messages.append(packaged_msg)

            tempString = updateMessages(keyring[selected_idx], temp[selected_tgt])

            window["_notepad"].update(tempString)

            # # add to the current display as outgoing message, Display the JSON in the notepad area.
            # #TODO: save this to conversation file as well
            # notepadText = values["_notepad"].encode('utf-8').decode('ascii')
            # if notepadText.strip() != "":
            #     notepadText += "\n"
            # window["_notepad"].update(notepadText+"["+account_name+"] - "+plaintext.decode('ascii')+"\n")
            
            #clear message box
            window["_messageBox"].update("")

        elif event == "New Account":
            ##TODO: post public key with our signature to pastebin. Save private key to a file. When posting public key it will return an ID that needs stored

            # Ask the user for the name of the keypair's owner
            owner = sg.popup_get_text(
                    "Enter the name of the user associated with this key:",
                    title = "Enter Key Owner Name")
            if owner == None:
                # The user clicked "Cancel"; stop processing this event.
                continue

            targetOwners = []
            for target in targets:
                targetOwners.append(target.owner)

            if targetOwners.__contains__(owner):
                sg.popup(f"This username is already in use.",
                    title = "This username is already in use.")
                continue

            # rsa_gen_keypair() will return an RSAPrivateKey object, which
            # includes both the public and private components of the keypair.
            keypair = crypto_backend.rsa_gen_keypair()

            # Add the key to the keyring. add_keyring_entry() will automatically
            # update the drop-down list of all the keys that have been loaded
            # into the app (and the "# loaded" label next to it).
            entry = KeyringEntry(keypair, owner)
            add_keyring_entry(entry)

            # Serialize the selected key's public component to PEM format.
            pem = crypto_backend.rsa_serialize_public_key(
                    entry.public)

            # Package the key in a JSON object that includes the associated owner
            # name.
            packaged_public_key = {
                    'owner': entry.owner,
                    'pubkey': pem
                    }
            jsonified_public = json.JSONEncoder().encode(packaged_public_key)

            post = json.loads(requests.post(baseUrl+create, data = {'contents': prefix+jsonified_public}).text) 

            packaged_private_key = {
                'id': post['id'],
                'owner': entry.owner,
                'private_key': crypto_backend.rsa_serialize_private_key(entry.private)
            }
            jsonified_private = json.JSONEncoder().encode(packaged_private_key)
            
            file = open('Accounts\\'+entry.owner+'.txt', 'w')
            file.write(jsonified_private)
            file.close()

            sg.popup(f"Successfully generated a new keypair for {owner}!",
                    title = "Successfully Generated Keypair")
            
        elif event == "_targetList" or event == "_keylist":
            selected_idx = window["_keylist"].widget.current()
            selected_tgt = window["_targetList"].widget.current()
            temp = []
            for target in targets:
                if len(keyring) <= 0 or target.owner != keyring[selected_idx].owner:
                    temp.append(target)
            window['_targetList'].update(values = compute_targetlist(temp), set_to_index = min(selected_tgt, len(temp)-1))
            if selected_idx in range(0, len(keyring)) and selected_tgt in range(0, len(targets)):
                tempString = updateMessages(keyring[selected_idx], temp[min(selected_tgt, len(temp)-1)])
                window["_notepad"].update(tempString)

            # selected_idx = window["_keylist"].widget.current()
            # selected_tgt = window["_targetList"].widget.current()
            # window['_targetList'].update(values = compute_targetlist(targets), set_to_index = min(selected_tgt, len(targets)-1))
            # if selected_tgt in range(0, len(targets)):
            #     tempString = updateMessages(keyring[selected_idx], targets[min(selected_tgt, len(targets)-1)])
            #     window["_notepad"].update(tempString)

    window.close()
    lastPost = open('System/lastPost.txt', 'w')
    lastPost.write(str(max))
    lastPost.close()
    saved = open('System/savedMessages.txt', 'w')
    json.dump(messages, saved)
    saved.close()
    
    contacts = open('System/contacts.txt', 'w')
    jsonTargets = [target.toJSON() for target in targets]
    json.dump(jsonTargets, contacts)
    contacts.close()

def liveUpdate():
    global max

    while True:
        time.sleep(5)
        minimum = max
        max = json.loads(requests.get(baseUrl+latest).text)['posts'][0]['id']
        if minimum != max:
            jsonized = json.loads(requests.get(baseUrl+viewRange+str(minimum)+'/'+str(max)).text)
            posts = jsonized['posts']        

            for post in posts:
                if(post['contents'][0:4] == 'bht-'):
                    contents = post['contents'][4:]
                    jsonizedPost =  json.loads(contents[3:])
                    if contents[0:3] == 'acc':
                        if targetlist_contains(jsonizedPost['owner']) == False:
                            add_target(KeyringEntry(key = crypto_backend.rsa_deserialize_public_key(jsonizedPost['pubkey']), owner = jsonizedPost['owner']))
                    elif contents[0:3] == 'msg':
                        if not keylist_contains(jsonizedPost['sender']):
                            messages.append(jsonizedPost)

            # selected_idx = window["_keylist"].widget.current()
            # selected_tgt = window["_targetList"].widget.current()
            # if selected_tgt not in range(0, len(targets)):
            #     sg.popup("No Target selected!")
            #     continue


            selected_idx = window["_keylist"].widget.current()
            selected_tgt = window["_targetList"].widget.current()
            temp = []
            for target in targets:
                if target.owner != keyring[selected_idx].owner:
                    temp.append(target)
            window['_targetList'].update(values = compute_targetlist(temp), set_to_index = min(selected_tgt, len(temp)-1))
            if selected_tgt in range(0, len(targets)):
                tempString = updateMessages(keyring[selected_idx], temp[min(selected_tgt, len(temp)-1)])
                window["_notepad"].update(tempString)
            # tempString = updateMessages(keyring[selected_idx], targets[selected_tgt])

            # window["_notepad"].update(tempString)

def decryptMessage(msg, private_key):
    try:
        # N.B.: The b64decode() function doesn't require us to explicitly
        # convert the string inputs into raw byte strings. Unlike
        # b64encode(), it will automatically interpret an input string as
        # ASCII (which is enough for the full base64 alphabet).
        encrypted_session_key = b64decode(
                msg['sessionkey'], validate = True)
        nonce = b64decode(msg['nonce'], validate = True)
        ciphertext = b64decode(msg['ciphertext'], validate = True)
    except binascii.Error:
        # This will only trigger if characters other than A-Z, a-z, 0-9,
        # +, or / (or = for length padding at the end) are found in the
        # input. Corruptions that produce a legitimate base64 character
        # cannot be detected and will silently change the data.
        #
        # (In the next project, we will learn how to use authenticated
        # encryption to detect corruption! 🙂)
        #
        # Note that we could have set validate = False (the default) in
        # the b64decode() calls above; but this will silently skip the
        # bad characters, which would render the entire rest of the
        # message unreadable (since the ciphertext would become
        # desynchronized with the keystream).
        sg.popup("Error: Invalid characters found in base64 input.",
                title = "Error Decrypting Message")
        return

    # Decrypt the session key using RSA, and then the message using AES
    # with the session key and nonce.
    try:
        plaintext = crypto_backend.decrypt_message_with_aes_and_rsa(
                private_key, encrypted_session_key, nonce, ciphertext)
    except ValueError as e:
        # The cryptography library threw an error trying to decrypt the
        # message. Report it and cancel.
        sg.popup_scrolled(e, title = "Error Decrypting Message")
        return
    return plaintext

baseUrl = 'http://cs448lnx101.gcc.edu'
create = '/posts/create'
        # field contents
view = '/posts/view/'#append int id
viewRange = '/posts/get/'# append <int:from_id>/<int:to_id>, maximum range 1000
latest = '/posts/get/latest'
delete = '/posts/delete/'#<int:id>

prefix = "bht-acc"

# A list of KeyringEntries (RSA keys) that have been loaded into the app.
keyring = []
targets = []

messages = []

max = 0

accountIndex = 0
targetIndex = 0

######################################################################
# Define the main window's layout and instantiate it
######################################################################

#sg.theme("gray gray gray") # Leaves all system defaults unchanged
#sg.theme("Dark Amber")
sg.theme("Light Green 5")

# Since we have to specify a monospace font by name for the notepad area and
# benchmark results, define this as a constant so it can be easily changed
# depending on what fonts you actually have available on your system.
#MONOSPACE_FONT = "Courier"
MONOSPACE_FONT = "Courier Prime" # Better font that I have installed on my machine

layout = [
        # [sg.Text("Enter plaintext, ciphertext, or public/private key:"),
        #  sg.Button("Clear"), sg.Push(), sg.Button("Run Benchmarks")],
        [sg.Multiline(size=(110,20), font=(MONOSPACE_FONT, 12),
                    key="_notepad", disabled = True)],
        [sg.InputText(size = (135, 1), key="_messageBox"),
        sg.Button("Send")],
        #    sg.Button("Encrypt"), sg.Button("Decrypt"),
        [sg.Text("Account:", key="_keyToUseLabel"),
        sg.Combo([], size=35, readonly=True, key="_keylist", enable_events=True),
        sg.Button("New Account"), #sg.Button("Import Account"),
        # sg.Button("Export Account to File"),
        sg.Text("Target:"), 
        sg.Combo([], size = 35, readonly = True, key="_targetList", enable_events=True)],
        ]

window = sg.Window("Encrypted Messenger", layout)

if __name__ == '__main__':
    window.finalize()
    for file in os.listdir('Accounts'):
        r = open('Accounts/'+file, 'r')
        account = json.loads(r.readline())
        add_keyring_entry(KeyringEntry(crypto_backend.rsa_deserialize_private_key(account['private_key']), account['owner'], account['id']))
        r.close()
    
    saved = open('System/savedMessages.txt', 'r')
    messages.extend(json.load(saved))
    saved.close()
    
    contacts = open('System/contacts.txt', 'r')
    targets.extend([JSONKeyring(contact) for contact in json.load(contacts)])
    contacts.close()
    window["_targetList"].update(values = compute_targetlist(targets), set_to_index = 0)
    
    max = json.loads(requests.get(baseUrl+latest).text)['posts'][0]['id']
    
    lastPost = open('System/lastPost.txt', 'r')
    minimum = int(lastPost.readline())
    lastPost.close()
    
    # just in case the pastebin gets over 1k posts
    while max-minimum >= 999:
        jsonized = json.loads(requests.get(baseUrl+viewRange+str(minimum)+'/'+str(minimum+998)).text)
        posts = jsonized['posts']
        
        for post in posts:
            if(post['contents'][0:4] == 'bht-'):
                contents = post['contents'][4:]
                jsonizedPost =  json.loads(contents[3:])
                if contents[0:3] == 'acc':
                    if targetlist_contains(jsonizedPost['owner']) == False:
                        add_target(KeyringEntry(key = crypto_backend.rsa_deserialize_public_key(jsonizedPost['pubkey']), owner = jsonizedPost['owner']))
                elif contents[0:3] == 'msg':
                    if not keylist_contains(jsonizedPost['sender']):
                        messages.append(jsonizedPost)
        minimum += 999

    jsonized = json.loads(requests.get(baseUrl+viewRange+str(minimum)+'/'+str(max)).text)
    posts = jsonized['posts']

    for post in posts:
        if(post['contents'][0:4] == 'bht-'):
            contents = post['contents'][4:]
            jsonizedPost =  json.loads(contents[3:])
            if contents[0:3] == 'acc':
                if targetlist_contains(jsonizedPost['owner']) == False:
                    add_target(KeyringEntry(key = crypto_backend.rsa_deserialize_public_key(jsonizedPost['pubkey']), owner = jsonizedPost['owner']))
            elif contents[0:3] == 'msg':
                    if not keylist_contains(jsonizedPost['sender']):
                        messages.append(jsonizedPost)

    selected_idx = window["_keylist"].widget.current()
    selected_tgt = window["_targetList"].widget.current()
    temp = []
    for target in targets:
        if len(keyring) <= 0 or target.owner != keyring[selected_idx].owner:
            temp.append(target)
    window['_targetList'].update(values = compute_targetlist(temp), set_to_index = min(selected_tgt, len(temp)-1))
    if selected_idx in range(0, len(keyring)) and selected_tgt in range(0, len(targets)):
        tempString = updateMessages(keyring[selected_idx], temp[min(selected_tgt, len(temp)-1)])
        window["_notepad"].update(tempString)

    # selected_idx = window["_keylist"].widget.current()
    # selected_tgt = window["_targetList"].widget.current()
    # window['_targetList'].update(values = compute_targetlist(targets), set_to_index = min(selected_tgt, len(targets)-1))
    # if selected_tgt in range(0, len(targets)):
    #     tempString = updateMessages(keyring[selected_idx], targets[min(selected_tgt, len(targets)-1)])
    #     window["_notepad"].update(tempString)

    target_update_thread = threading.Thread(target=liveUpdate, daemon=True)
    target_update_thread.start()

    MainLoop()

    # jsonized = json.loads(requests.get(baseUrl+viewRange+'0/700').text)
    # posts = jsonized['posts']        

    # for post in posts:
    #     if(post['contents'][0:7] == prefix):
    #         print(str(post['id']) + ' deleted')
    #         json.loads(requests.post(baseUrl+delete+str(post['id']), data = {'hash' : hashlib.sha1(post['contents'].encode('utf-8')).hexdigest()}).text)
