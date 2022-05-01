# https://github.com/dspruell/aslookup
from aslookup import get_as_data
ip = "8.8.8.8"

print(get_as_data(ip))
print(get_as_data(ip, service="shadowserver"))

print(get_as_data("23456"))
