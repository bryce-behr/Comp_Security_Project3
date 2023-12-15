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
