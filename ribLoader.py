"""
https://www.mongodb.com/blog/post/getting-started-with-python-and-mongodb
"""

from pymongo import MongoClient
from mrtparse import *
import parserHelper
import time


def mongoConnect():
    configFile = open("mongoconnect.txt", "r")
    mongoUrl = configFile.readline()
    print("Connecting to: ", mongoUrl)
    configFile.close()

    client = MongoClient(mongoUrl)
    db = client.bgpdata
    return db

def main():
    
    # db = mongoConnect()

    # insertData = {}
    args = parserHelper.parse_args()
    tic = time.perf_counter()
    
    sys.stdout.write('[\n')
    i = 0
    for entry in Reader(sys.argv[1]):

        insertData = {}
        insertData = parserHelper.parseData(entry, args, i)
        # TODO batch this insert
        # result = db.bgpdata.insert_one(insertData)
        
        i += 1
        if (i % 100 == 0):
            print(i)
            # break
    sys.stdout.write('\n]\n')
    toc = time.perf_counter()
    print(f"Loaded all {i} announcements in {toc - tic:0.4f} seconds")


if __name__ == '__main__':
    main()
