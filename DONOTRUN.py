import os

lastPost = open('System/lastPost.txt', 'w')
lastPost.write(str(0))
lastPost.close()

# for file in os.listdir('Accounts'):
#     r = os.remove('Accounts/'+file)