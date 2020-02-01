import  requests, pprint

# payload_0 = {
#     "action": "list_customer",
# }
# response = requests.get('http://localhost/api/mgr/customers', params = payload_0)
# pprint.pprint(response.json())

# 构建查看 客户信息的消息体
response = requests.get('http://localhost/api/mgr/customers?action=list_customer')
# 发送请求给web服务
pprint.pprint(response.json())

# 构建添加 客户信息的 消息体，是json格式
# payload_1 = {
#     "action": "add_customer",
#     "data":{
#         "name":"武汉市桥西医院",
#         "phonenumber":"13345679934",
#         "address":"武汉市桥西医院北路"
#     }
# }

# response = requests.post('http://localhost/api/mgr/customers', json=payload_1)
# pprint.pprint(response.json())
# response = requests.get('http://localhost/api/mgr/customers?action=list_customer')
# pprint.pprint(response.json())

payload_2 = {
    "action":"modify_customer",
    "id": 6,
    "newdata":{
        "name":"武汉市桥北医院",
        "phonenumber":"13345678888",
        "address":"武汉市桥北医院北路"
    }
}
response = requests.post('http://localhost/api/mgr/customers', json=payload_2)
pprint.pprint(response.json())
response = requests.get('http://localhost/api/mgr/customers?action=list_customer')
pprint.pprint(response.json())


# 构建删除 客户信息的 消息体，是json格式
# payload_3 = {
#     "action": "del_customer",
#     "id": 5
# }

# # 发送请求给web服务
# response = requests.post('http://localhost/api/mgr/customers', json=payload_3)
# pprint.pprint(response.json())
#
# response = requests.get('http://localhost/api/mgr/customers?action=list_customer')
# pprint.pprint(response.json())