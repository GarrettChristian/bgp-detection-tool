"""
------------------------------------------

Detection Tool

------------------------------------------
"""

import collections
import re
from sys import prefix
from tabnanny import verbose
from turtle import up
from pymongo import MongoClient
from mrtparse import *
import parserHelper
import time
import glob
import json
from commonUtil import formatSecondsToHhmmss, mongoConnect
import ipaddress
from ipaddress import ip_network, ip_address, IPv4Address
import argparse
import uuid

# ------------------------------------------

# Global variables
db = None
bgpcollection = None
trackedPrefixes = set()
dedup = {}
batchId = str(uuid.uuid4())
updatesToSave = []
args = {}
hijackCount = 0
hijackCountUpdateFile = 0

def parse_args():
    p = argparse.ArgumentParser(
        description='Update Parser for the BGP Detection Tool')
    p.add_argument(
        'update_dir', help='Path to the update directory')
    p.add_argument(
        'mongo_collection', help='Mongo db collection name')
    p.add_argument(
        '-v', action='store_true', help='Enable verbose logging')
    
    return p.parse_args()


"""
Gets all the prefixes we're tracking
"""
def populateTrackedPrefixes():
    print("Creating the set of prefixes we're tracking")

    allPrefixes = set()
    nlri = bgpcollection.find({}, { "_id": 0, "nlri": 1 })

    for prefixList in nlri:
        for prefix in prefixList["nlri"]:
            allPrefixes.add(prefix)

    return allPrefixes



"""
Processes a list of update files
"""
def processUpdateFiles(dir):

    totalUpdateCount = 0

    updateFiles = glob.glob(dir + "/updates*.bz2")
    # updateFiles = glob.glob(dir + "/updates.20220307.1200.bz2")
    
    # Order the update files cronologically
    updateFiles = sorted(updateFiles)

    if (args.v):
        print("Update Files:")
        for i, updateFile in enumerate(updateFiles):
            print(f"{i + 1} {updateFile}")

    print("\n------------------------------\n\n")
    
    for i, updateFile in enumerate(updateFiles):
        print(f"Starting Processing on {i + 1} / {len(updateFiles)}: {updateFile}")
        totalUpdateCount += processUpdateFile(updateFile)
        print(f"Finished Processing on {i + 1} / {len(updateFiles)}: {updateFile}")
        print("\n------------------------------\n\n")
        
    return totalUpdateCount


"""
Handles one update file
"""
def processUpdateFile(updateFile):

    updateCount = 0
    for entry in Reader(updateFile):

        update = parserHelper.parseData(entry, updateCount)
        processUpdate(update, updateCount, updateFile)

        updateCount += 1

    saveUpdates()
    
    return updateCount


"""
Handles one specific update

Checking for prefix hijacks

"""
def processUpdate(update, num, updateFile):
    global updatesToSave
    global dedup    
    global hijackCount
    global hijackCountUpdateFile

    # Must have an origin to be announcing
    if "as_origin" in update.keys():

        # For every prefix announced for this origin
        for prefix in update["nlri"]:

            # Check if we have hijack larger prefix varient 
            prefixListLarger = getLargerPrefixes(prefix)

            matchCase = ""
            matchingPrefix = None

            for prefixLarge in prefixListLarger:
                if prefixLarge in trackedPrefixes:
                    matchingPrefix = prefixLarge
                    matchCase = "larger"

            # Check if we have an exact match ie could be hijack or path poison
            if prefix in trackedPrefixes:
                matchingPrefix = prefix
                matchCase = "exact"


            # If we match any of the prefixes we're tracking
            if matchingPrefix != None:

                updateOrigin = update["as_origin"]
                curItem = (prefix, updateOrigin)

                # Something we've seen before in this update
                if curItem in dedup:
                    dedup[curItem] = dedup[curItem] + 1

                # New occurance 
                else:
                    # only check our initial rib
                    query = {"nlri": matchingPrefix, "updateFileName": { "$exists": False } }
                    results = bgpcollection.find(query)

                    for announcement in results:
                        announcementOrigin = announcement["as_origin"]

                        if announcementOrigin != updateOrigin:
                            # TODO check for diff origin for prefix hijack
                            # TODO check ROA

                            hijackCount += 1
                            hijackCountUpdateFile += 1

                            print("%d Hijack - Prefix rib[%s] update[%s] (%s match), Origin does not match rib[%s] update[%s]"  % (hijackCount, announcement["nlri"][0], prefix, matchCase, announcementOrigin, updateOrigin))

                            # Check past occurances
                            query = {"asOrigin": updateOrigin}
                            previousOriginResult = bgpcollection.find(query)
                            previousOrigin = list(previousOriginResult)
                            if len(previousOrigin) != 0:
                                print(f"\tUpdate origin {updateOrigin} has a saved announcement already for:")
                                for prev in previousOrigin:
                                    if ("count" in prev.keys()):
                                        print("\t\t%s - %d " % (prev["nlri"][0], prev["count"]))
                                    else:
                                        print("\t\t%s - (RIB)" % (prev["nlri"][0]))
                    
                            saveUpdate = {}
                            saveUpdate["_id"] = str(uuid.uuid4())
                            saveUpdate["updateFileName"] = updateFile
                            saveUpdate["timestamp"] = update["timestamp"]
                            saveUpdate["originated_time"] = update["originated_time"]
                            saveUpdate["nlri"] = announcement["nlri"]
                            saveUpdate["matchedPrefix"] = prefix
                            saveUpdate["as_path"] = update["as_path"]
                            saveUpdate["as_origin"] = update["as_origin"]
                            saveUpdate["communities"] = update["communities"]
                            saveUpdate["batchId"] = batchId

                            updatesToSave.append(saveUpdate)

                            dedup[curItem] = 1

                            

                        else:
                            if (args.v):
                                print("%d Prefix rib[%s] update[%s] (%s) match, Origin matches %s" % (num, announcement["nlri"][0], prefix, matchCase, announcementOrigin))

                            # TODO check path
                            # TODO check communities

                            saveUpdate = {}
                            saveUpdate["_id"] = str(uuid.uuid4())
                            saveUpdate["updateFileName"] = updateFile
                            saveUpdate["timestamp"] = update["timestamp"]
                            saveUpdate["originated_time"] = update["originated_time"]
                            saveUpdate["nlri"] = announcement["nlri"]
                            saveUpdate["matchedPrefix"] = prefix
                            saveUpdate["as_path"] = update["as_path"]
                            saveUpdate["as_origin"] = update["as_origin"]
                            saveUpdate["communities"] = update["communities"]
                            saveUpdate["batchId"] = batchId

                            updatesToSave.append(saveUpdate)
                            
                            dedup[curItem] = 1

"""
"An AS could advertise a more specific prefix than the one being 
advertised by the owner and this would hijack all the traffic to the specific prefix. 
However, the hijacking AS would not be able route this traffic onto the owner and hence, 
interception would not be possible."
- A Study of Prefix Hijacking and Interception in the Internet

This finds all larger prefixes to look for the above type of hijack attack 
This is the google 2008 attack observed in HW2
"""
def getLargerPrefixes(addressPrefix):

    pathSplit = addressPrefix.split('/')

    address = pathSplit[0]
    prefixLength = int(pathSplit[1])

    prefixes = []
    
    # IPv4
    if type(ip_address(address)) is IPv4Address:
        for newPrefix in range (16, prefixLength + 1):
            supernet = ip_network(addressPrefix).supernet(new_prefix=newPrefix)
            prefixes.append(str(supernet))
        
    else: # "AFI_IPv6"
        # TODO - choosing to ingore for now
        prefixes = []


    return prefixes

"""
"An AS could advertise a less specific prefix than the one being advertised by the owner. 
This would hijack traffic to the prefix only when the owner withdraws its advertisements. 
However, even in that situation, 
the hijacking AS would not be able to route the hijacked traffic to the owner."
- A Study of Prefix Hijacking and Interception in the Internet

This finds all smaller prefixes to look for the above type of hijack attack 


DEPRECATED - 2^n, op where n is
"""
def getSmallerPrefixes(addressPrefix):

    pathSplit = addressPrefix.split('/')

    address = pathSplit[0]
    prefixLength = int(pathSplit[1])

    prefixes = []
    
    # IPv4
    if type(ip_address(address)) is IPv4Address:
        for newPrefix in range (prefixLength + 1, 24):
            subnets = ip_network(addressPrefix).subnets(new_prefix=newPrefix)
            for subnet in subnets:
                prefixes.append(str(subnet))
        
    else: # "AFI_IPv6"
        # TODO - choosing to ingore for now
        prefixes = []


    return prefixes

def saveUpdates():
    global updatesToSave
    global dedup
    global hijackCountUpdateFile

    for update in updatesToSave:
        curItem = (update["matchedPrefix"], update["as_origin"])
        update["count"] = dedup[curItem]
        

    print("Saving %d updates " % (len(updatesToSave)))
    bgpcollection.insert_many(updatesToSave)
    updatesToSave = []
    print("Reseting dedup")
    print("Found %d possible hijacks so far and %d in this file" % (hijackCount, hijackCountUpdateFile))
    hijackCountUpdateFile = 0
    dedup = {}


def main():
    global db
    global bgpcollection
    global trackedPrefixes
    global args

    print("\n\nStarting BGP Detection Tool\n\n")

    args = parse_args()
    print("Parsing Updates from: ", args.update_dir)
    
    # Connect to database
    # Note is expected that the loader has been run first
    # TODO could add diff collections for the diff days we're examining 
    db = mongoConnect("bgpdata")
    bgpcollection = db[args.mongo_collection]
    print("Connected to bgpdata and collection ", args.mongo_collection)

    # Start timer
    tic = time.perf_counter()

    # Get all the prefixes we're tracking
    trackedPrefixes = populateTrackedPrefixes()
    
    # Process updates
    updateCount = processUpdateFiles(args.update_dir)

    # End timer
    toc = time.perf_counter()
    timeSeconds = toc - tic
    timeFormatted = formatSecondsToHhmmss(timeSeconds)

    print("\n------------------------------")
    print(f"Loaded all {updateCount} updates in {timeFormatted} seconds")


if __name__ == '__main__':
    main()

