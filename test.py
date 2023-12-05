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

fields = {'contents': 'testing: I like pancakes'}
print(fields)
x = requests.post(baseUrl+create, data = fields)

print(x.text)