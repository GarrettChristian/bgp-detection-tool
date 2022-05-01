"""
https://www.mongodb.com/blog/post/getting-started-with-python-and-mongodb
"""

from sys import prefix
from pymongo import MongoClient
from mrtparse import *
import parserHelper
import time
from commonUtil import formatSecondsToHhmmss, mongoConnect
import json
import argparse
import uuid


def parse_args():
    p = argparse.ArgumentParser(
        description='RIB Loader for the BGP Detection Tool')
    p.add_argument(
        'rib_file', help='Path to the RIB file')
    p.add_argument(
        'mongo_collection', help='Mongo db collection name')
    
    return p.parse_args()

def main():

    print("Starting RIB Loader")

    args = parse_args()
    print("Parsing RIB: ", args.rib_file)
    
    # Connect to db and specific collection
    db = mongoConnect("bgpdata")
    bgpCol = db[args.mongo_collection]
    print("Connected to bgpdata and collection ", args.mongo_collection)

    # Start timer
    tic = time.perf_counter()
    
    # Prepare the batch insert array and set of prefixes
    randomSampleBatch = []
    batchId = str(uuid.uuid4())
    ipPrefixSet = set()
    # Counters for how many we've seen / added
    i = 0
    addedCount = 0

    for entry in Reader(args.rib_file):
        
        # You are the 1000th 
        if (i % 100 == 0):

            insertData = {}
            insertData = parserHelper.parseData(entry, i)
            # print(json.dumps([insertData], indent=2))

            # We have not saved this prefix to monitor already
            if (len(insertData["nlri"]) > 0) and (insertData["nlri"][0] not in ipPrefixSet):
                addedCount += 1
                print(f"{i}, {addedCount} added: {insertData['peer_ip']} with prefix ", insertData["nlri"][0])
                ipPrefixSet.add(insertData["nlri"][0])
                insertData["batchId"] = batchId
                randomSampleBatch.append(insertData)
            
                # Batched insert
                if (len(randomSampleBatch) == 200):
                    bgpCol.insert_many(randomSampleBatch)
                    randomSampleBatch = []

        i += 1

    if (len(randomSampleBatch) != 0):
        bgpCol.insert_many(randomSampleBatch)

    toc = time.perf_counter()
    timeSeconds = toc - tic
    timeFormatted = formatSecondsToHhmmss(timeSeconds)
    print(f"Loaded all {i} announcements in {timeFormatted} seconds saving {addedCount} distinct prefixes {len(ipPrefixSet)}")

if __name__ == '__main__':
    main()




# Old heruistics to add:
# if (insertData["nlri"][0]) in ipPrefixSet:
#     print(f"{i}, {addedCount} another from diff ip {insertData['peer_ip']} for prefix ", insertData["nlri"][0])
#     addedCount += 1

# Ranomly sample ever 1000th or if you're the specific google example

# if (i % 1000 == 0 or (insertData['peer_ip'] == "81.209.156.1" and insertData["nlri"][-1] == "208.65.152.0/22")):