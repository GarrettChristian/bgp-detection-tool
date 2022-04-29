import whois


w = whois.whois("203.98.25.0")


w.text
print(w)



import socket
ip = socket.gethostbyname("203.98.25.0")
from cymruwhois import Client

c=Client()

r=c.lookup(ip)
print(r.asn)

print(r.owner)

 

