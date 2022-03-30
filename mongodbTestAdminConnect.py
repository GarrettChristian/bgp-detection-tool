"""
https://www.mongodb.com/blog/post/getting-started-with-python-and-mongodb
"""

from pymongo import MongoClient

from pprint import pprint


configFile = open("mongoconnect.txt", "r")
mongoUrl = configFile.readline()
print("Connecting to: ", mongoUrl)
configFile.close()


# connect to MongoDB, change the << MONGODB URL >> to reflect your own connection string
client = MongoClient(mongoUrl)
db=client.admin
# Issue the serverStatus command and print the results
serverStatusResult=db.command("serverStatus")
pprint(serverStatusResult)