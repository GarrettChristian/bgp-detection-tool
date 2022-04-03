"""
https://www.mongodb.com/blog/post/getting-started-with-python-and-mongodb
"""

from pymongo import MongoClient
from mrtparse import *
import parserHelper
import time


"""
formatSecondsToHhmmss
Helper to convert seconds to hours minutes and seconds
@param seconds
@return formatted string of hhmmss
"""
def formatSecondsToHhmmss(seconds):
    hours = seconds / (60*60)
    seconds %= (60*60)
    minutes = seconds / 60
    seconds %= 60
    return "%02i:%02i:%02i" % (hours, minutes, seconds)

def mongoConnect():
    configFile = open("mongoconnect.txt", "r")
    mongoUrl = configFile.readline()
    print("Connecting to: ", mongoUrl)
    configFile.close()

    client = MongoClient(mongoUrl)
    db = client.bgpdata
    return db

def main():

    # In google rib there are 10191400
    print("Starting RIB Loader")
    
    db = mongoConnect()

    # insertData = {}
    args = parserHelper.parse_args()
    tic = time.perf_counter()
    
    randomSampleBatch = []
    ipPrefixSet = set()

    print("Parsing RIB")
    i = 0
    addedCount = 0
    for entry in Reader(sys.argv[1]):

        insertData = {}
        insertData = parserHelper.parseData(entry, args, i)
        if (insertData["nlri"][0]) in ipPrefixSet:
            print(f"{i}, {addedCount} another from diff ip {insertData['peer_ip']} for prefix ", insertData["nlri"][0])
            addedCount += 1
        
        i += 1
        if (i % 1000 == 0):
            addedCount += 1
            print(f"{i}, {addedCount} first from ip {insertData['peer_ip']} with prefix ", insertData["nlri"][0])
            ipPrefixSet.add((insertData['peer_ip'], insertData["nlri"][0]))
            randomSampleBatch.append(insertData)
            
        # Batched insert
        if (len(randomSampleBatch) == 200):
                db.bgpdata.insert_many(randomSampleBatch)
                randomSampleBatch = []

    if (len(randomSampleBatch) != 0):
        db.bgpdata.insert_many(randomSampleBatch)

    toc = time.perf_counter()
    timeSeconds = toc - tic
    timeFormatted = formatSecondsToHhmmss(timeSeconds)
    print(f"Loaded all {i} announcements in {timeFormatted} seconds saving {addedCount}")
    print(len(ipPrefixSet))

if __name__ == '__main__':
    main()
