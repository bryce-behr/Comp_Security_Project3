import json
import encrypted_messenger
targets = []
contacts = open('System/contacts.txt', 'r')
print(json.load(contacts)[0]['owner'])
contacts.close()
