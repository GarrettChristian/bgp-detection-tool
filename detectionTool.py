"""
------------------------------------------

Detection Tool

------------------------------------------
"""

import collections
import re
from sys import prefix
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

# ------------------------------------------

# Global variables
db = None
bgpcollection = None
detectedAttacks = {}

def parse_args():
    p = argparse.ArgumentParser(
        description='Update Parser for the BGP Detection Tool')
    p.add_argument(
        'update_dir', help='Path to the update directory')
    p.add_argument(
        'mongo_collection', help='Mongo db collection name')
    
    return p.parse_args()


"""
Processes a list of update files
"""
def processUpdateFiles(dir):

    totalUpdateCount = 0

    updateFiles = glob.glob(dir + "/updates*.bz2")
    
    # Order the update files cronologically
    updateFiles = sorted(updateFiles)

    print("Update Files:")
    for i, updateFile in enumerate(updateFiles):
        print(f"{i + 1} {updateFile}")
    
    for i, updateFile in enumerate(updateFiles):
        print(f"Starting Processing on {i + 1} / {len(updateFiles)}: {updateFile}")
        totalUpdateCount += processUpdateFile(updateFile)
        print(f"Finished Processing on {i + 1} / {len(updateFiles)}: {updateFile}")
        
    return totalUpdateCount


"""
Handles one update file
"""
def processUpdateFile(updateFile):

    updateCount = 0
    for entry in Reader(updateFile):

        # Convert to dictionary
        updateData = parserHelper.parseData(entry, updateCount)
        processUpdate(updateData)

        updateCount += 1
    
    return updateCount


"""
Handles one specific update

Currently only checks for prefix hijck attacks

"""
def processUpdate(update):
    global detectedAttacks

    # TODO could examine withdraws, currently not differentiating 

    # Must have an as origin
    if "as_origin" in update.keys():
        asOrigin = update["as_origin"]

        # For every prefix announced by this origin
        for prefix in update["nlri"]:

            # Already detected
            if ((prefix, asOrigin) in detectedAttacks.keys()):
                count = detectedAttacks.get((prefix, asOrigin), 0)
                detectedAttacks[(prefix, asOrigin)] = count + 1

            # Check against db 
            else:
                # Varient 1
                prefixListLarger = getLargerPrefixes(prefix)
                # TODO varient 2, I think smaller might be difficult onlly because it produces a lot of possible
                # varients which could be difficult with the $in query that has to check against everythin
                # we could concievbly change this to a clever regex then check on actual matches after
                # trade off there is that it could be pulling more than we need to
                # Another option is we could redo the db schema 
                # to track each related announcement as a list with the prefix as the id, this could make saving easier 
                # prefixListSmaller = getSmallerPrefixes(prefix)

                prefixList = prefixListLarger + [prefix]

                # a different origin 
                # the same, shorter, or longer version of this prefix 
                query = {"as_origin": {"$ne": asOrigin}, "nlri": {"$in": prefixList}}
                # print(query)
                results = bgpcollection.find(query)

                # TODO post processing for longer short same 

                for announcement in results:
                    printAttackInfo(update, prefix, announcement)

                    # Check to see if this prefix has announced this AS before
                    query = {"as_origin": asOrigin, "nlri": prefix}
                    result = bgpcollection.find_one(query)
                    if (result != None):
                        print(f"{asOrigin} has announced {prefix} before")


                # TODO add varient 2 getSmallerPrefixes
                # TODO add checks to see if the prefix is the same, since this can be an example of SICO path, check comm
                # TODO could also check for path attacks, rather than seeing if origin is different 
                # TODO advertising an invalid route
                # TODO ROA / RPKI
    
    # TODO save based on prefix if its in query = {"nlri": {"$in": prefixList}}
    # Save


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
        # TODO!
        prefixes = []


    return prefixes

"""
"An AS could advertise a less specific prefix than the one being advertised by the owner. 
This would hijack traffic to the prefix only when the owner withdraws its advertisements. 
However, even in that situation, 
the hijacking AS would not be able to route the hijacked traffic to the owner."
- A Study of Prefix Hijacking and Interception in the Internet

This finds all smaller prefixes to look for the above type of hijack attack 
"""
def getSmallerPrefixes(addressPrefix):

    pathSplit = addressPrefix.split('/')

    address = pathSplit[0]
    prefixLength = int(pathSplit[1])

    prefixes = []
    
    # IPv4
    if type(ip_address(address)) is IPv4Address:
        for newPrefix in range (prefixLength + 1, 32):
            subnets = ip_network(addressPrefix).subnets(new_prefix=newPrefix)
            for subnet in subnets:
                prefixes.append(str(subnet))
        
    else: # "AFI_IPv6"
        # TODO!
        prefixes = [addressPrefix]


    return prefixes


"""
Prints the important information related to the hijack attack
"""
def printAttackInfo(update, updatePrefix, announcement):
    global detectedAttacks

    print("\n------------------------------")
    print("Potential Hijack Attack Detected!")
    print("Update")
    print("Origin", update["as_origin"])
    print("Prefix", updatePrefix)
    # print(json.dumps([update], indent=2))

    print("RIB")
    print("Origin", announcement["as_origin"])
    print("Prefix", announcement["nlri"])
    # print(json.dumps([announcement], indent=2))
        
        
    # update the occurances of this detection
    detectedAttacks[(updatePrefix, update["as_origin"])] = 1
    


def main():
    global db
    global bgpcollection

    print("Starting BGP Detection Tool")

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
    
    # Process updates
    updateCount = processUpdateFiles(args.update_dir)

    # End timer
    toc = time.perf_counter()
    timeSeconds = toc - tic
    timeFormatted = formatSecondsToHhmmss(timeSeconds)

    print("\n------------------------------")
    for pair in detectedAttacks:
        print("%d repeats of %s, %s" % ((detectedAttacks[pair]), pair[0], pair[1]))

    print("\n------------------------------")
    print(f"Loaded all {updateCount} updates in {timeFormatted} seconds")


if __name__ == '__main__':
    main()

