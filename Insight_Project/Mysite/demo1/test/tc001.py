import requests, pprint

payload = {
    'username': 'user',
    'password': 'zyx213416'
}

payload2 = {
    'username': 'user',
    'password': 'zyx21341'
}

response = requests.post('http://localhost/api/mgr/signin', data=payload)
response2 = requests.post('http://localhost/api/mgr/signin', data=payload2)

pprint.pprint(response.json())
pprint.pprint(response2.json())
