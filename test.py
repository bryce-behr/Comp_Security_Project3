# example post request
import requests

baseUrl = 'http://cs448lnx101.gcc.edu/'
create = '/posts/create'
        # field contents
view = '/posts/view/'#append int id
viewRange = '/posts/get/'# append <int:from_id>/<int:to_id>, maximum range 1000
latest = '/posts/get/latest'
delete = '/posts/delete/<int:id>'
        #field hash = SHA-1 hash of contents

x = None
#fields = {'contents': 'testing: I like pancakes'}
#print(fields)
#x = requests.post(baseUrl+create, data = fields)
x = requests.get(baseUrl+view+"608")
#x = requests.get(baseUrl+viewRange+"226"+"/"+"250")
#x = requests.get(baseUrl+latest)

try:
    print(x.json()['contents']) 
except:
    print("error")