from urllib import request
import requests
import json

# https://www.w3schools.com/python/ref_requests_response.asp

prefix = "208.65.152.0/22"
originASN = "36561"
# getRequest = "https://rpki-validator.ripe.net/api/v1/validity/" + originASN + "/" + prefix
getRequest = "http://localhost:8323/api/v1/validity/" + originASN + "/" + prefix

x = requests.get(getRequest)
print(x.status_code)
print(print(json.dumps(x.json(), indent=2)))
data = x.json()
print(data)
print(data['validated_route']["validity"]["state"])







