"""
------------------------------------------

BGP Detection Tool

------------------------------------------
"""

from pymongo import MongoClient
from mrtparse import *
import parserHelper
import time
import glob
from commonUtil import formatSecondsToHhmmss, mongoConnect
from ipaddress import ip_network, ip_address, IPv4Address
import argparse
import uuid
import socket
import requests
from cymruwhois import Client


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
Processes a directory of update files
"""
def processUpdateFiles(dir):

    totalUpdateCount = 0

    updateFiles = glob.glob(dir + "/updates*.bz2")
    
    # Order the update files cronologically
    updateFiles = sorted(updateFiles)

    if (args.v):
        print("Update Files:")
        for i, updateFile in enumerate(updateFiles):
            print(f"{i + 1} {updateFile}")

    print("\n------------------------------\n\n")
    
    # Process each update file
    for i, updateFile in enumerate(updateFiles):
        print(f"Starting Processing on {i + 1} / {len(updateFiles)}: {updateFile}\n\n")
        tic = time.perf_counter()

        # handle the update file
        totalUpdateCount += processUpdateFile(updateFile)

        toc = time.perf_counter()
        timeSeconds = toc - tic
        timeFormatted = formatSecondsToHhmmss(timeSeconds)
        print(f"Finished Processing on {i + 1} / {len(updateFiles)}: {updateFile} in {timeFormatted} seconds")
        
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

            # Check for the large match an example would be google
            for prefixLarge in prefixListLarger:
                if prefixLarge in trackedPrefixes:
                    matchingPrefix = prefixLarge
                    matchCase = "Larger"

            # Check if we have an exact match ie could be hijack or path poison
            if prefix in trackedPrefixes:
                matchingPrefix = prefix
                matchCase = "Exact"


            # If we match any of the prefixes we're tracking
            if matchingPrefix != None:

                updateOrigin = update["as_origin"]
                curItem = (prefix, updateOrigin)

                # Something we've seen before in this update
                if curItem in dedup:
                    dedup[curItem] = dedup[curItem] + 1

                # New occurance 
                else:
                    # only check our initial rib collection
                    query = {"nlri": matchingPrefix, "updateFileName": { "$exists": False } }
                    results = bgpcollection.find(query)

                    for announcement in results:
                        announcementOrigin = announcement["as_origin"]

                        if announcementOrigin != updateOrigin:

                            hijackCount += 1
                            hijackCountUpdateFile += 1

                            print("%-5d Potential Hijack " % (hijackCount))
                            print("\tPrefix | RIB %-18s | Update %-18s | %-6s match |" % (announcement["nlri"][0], prefix, matchCase))
                            print("\tOrigin | RIB %-18s | Update %-18s |"  % (announcementOrigin, updateOrigin))

                            # Check against whois
                            whoisCheck(announcement["nlri"][0], prefix, announcementOrigin, updateOrigin)

                            routinatorCheck(prefix, updateOrigin)
      
                            # Check past occurances in our database
                            query = {"as_origin": updateOrigin}
                            previousOrigin = bgpcollection.find(query)
                            prevRibCount = 0
                            prevUpdateSaved = 0
                            prevUpdateCount = 0
                            prevUpdateSavedThisPrefix = 0
                            prevUpdateCountThisPrefix = 0
                            for prev in previousOrigin:
                                if ("count" in prev.keys()):
                                    prevUpdateSaved += 1
                                    prevUpdateCount += prev["count"]
                                    if (prev["matchedPrefix"] == prefix):
                                        prevUpdateSavedThisPrefix += 1
                                        prevUpdateCountThisPrefix += prev["count"]
                                else:
                                    prevRibCount += 1

                            if (prevRibCount > 0 or prevUpdateCount > 0):
                                print("\t\t\tFor Update origin %-6s previously seen: " % (updateOrigin))
                                print("\t\t\t\t%-5d RIB announcements" % (prevRibCount))
                                print("\t\t\t\t%-5d Updates saved for origin          | %-5d Update count for origin" % (prevUpdateSaved, prevUpdateCount))
                                print("\t\t\t\t%-5d Updates saved for origin & prefix | %-5d Updates count for origin & prefix" % (prevUpdateSavedThisPrefix, prevUpdateCountThisPrefix))
                            print("")
                            print("")


                            # Prepare update to save
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


                        # Same origin
                        else:
                            if (args.v):
                                print("%d Prefix rib[%s] update[%s] (%s) match, Origin matches %s" % (num, announcement["nlri"][0], prefix, matchCase, announcementOrigin))

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
Checks the who is data for the announcement and update using cym
Redundent calls are caught by cyms caching
"""
def whoisCheck(announcementPrefix, prefix, announcementOrigin, updateOrigin):

    cymClient = Client()

    ribPrefix = announcementPrefix.split("/")[0]
    ip = socket.gethostbyname(ribPrefix)
    upPrefix = prefix.split("/")[0]
    ipUp = socket.gethostbyname(upPrefix)
    asOrig = "AS" + announcementOrigin
    asUp = "AS" + updateOrigin

    results = list(cymClient.lookupmany([ip, ipUp, asOrig, asUp]))    

    try:
        print("\t\t%-14s | %-18s | %s" % ("RIB prefix", ribPrefix, results[0]))
        print("\t\t%-14s | %-18s | %s" % ("Update prefix", upPrefix, results[1]))
        print("\t\t%-14s | %-18s | %s" % ("RIB origin", asOrig, results[2]))
        print("\t\t%-14s | %-18s | %s" % ("Update origin", asUp, results[3]))
    except:
        # No op
        i = 1

"""
Checks the route origin authorization using routinator
"""
def routinatorCheck(prefix, updateOrigin):

    getRequestUpdate = "http://localhost:8323/api/v1/validity/" + updateOrigin + "/" + prefix

    try:
        routinatorUpdate = requests.get(getRequestUpdate)
        data = routinatorUpdate.json()
        valid = data['validated_route']["validity"]["state"]
        print("\t\tRoutinator for Update is: %s" % (valid))
    except:
        # No op
        i = 1

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

"""
Saves the updates that are relevant to our tracked prefixes
"""
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

    print("\n\n------------------------------")
    print("\n\nStarting BGP Detection Tool\n\n")

    args = parse_args()
    print("Parsing Updates from: ", args.update_dir)
    
    # Connect to database
    # Note is expected that the loader has been run first
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

