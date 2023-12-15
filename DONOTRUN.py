import os

lastPost = open('System/lastPost.txt', 'w')
lastPost.write(str(0))
lastPost.close()

lastPost = open('System/savedMessages.txt', 'w')
lastPost.write("[]")
lastPost.close()

lastPost = open('System/contacts.txt', 'w')
lastPost.write("[]")
lastPost.close()


# for file in os.listdir('Accounts'):
#     r = os.remove('Accounts/'+file)