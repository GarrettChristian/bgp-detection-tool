import socket

ip = socket.gethostbyname("www.google.com")

from cymruwhois import Client

c=Client()
# r=c.lookup(ip)
r=c.lookup("AS15169")

print(r.owner)
print(r.cc)
print(r)