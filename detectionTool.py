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

# ------------------------------------------

# Global variables
args = parserHelper.parse_args()
db = None
bgpcollection = None
detectedAttacks = {}

"""
Processes a list of update files
"""
def processUpdateFiles(dir):

    totalUpdateCount = 0

    updateFiles = glob.glob(dir + "/updates*.bz2")
    # TODO order these cronologically
    
    for updateFile in updateFiles:
        print(f"Starting Processing on {updateFile}")
        totalUpdateCount += processUpdateFile(updateFile)
        print(f"Finished Processing on {updateFile}")
        
    return totalUpdateCount    


"""
Handles one update file
"""
def processUpdateFile(updateFile):

    updateCount = 0
    for entry in Reader(updateFile):

        # Convert to dictionary
        updateData = parserHelper.parseData(entry, args, updateCount)
        processUpdate(updateData)

        updateCount += 1
    
    return updateCount


"""
Handles one specific update
"""
def processUpdate(update):

    checkForPrefixHijack(update)
    # TODO add other checks for diff attacks?

    # TODO when is this saved? always?
    # Probably check if this is a shorter version of one of our tracked prefixes save then?
    # db.bgpdata.insert_one(update)


"""
Checks to see if there was a hijack
"""
def checkForPrefixHijack(update):
    global detectedAttacks

    # print("Update", update["nlri"])
    # print(json.dumps([update], indent=2))

    # Must have an origin
    if "as_origin" in update.keys():
        asOrigin = update["as_origin"]
        # if (asOrigin == "17557"):
        #     print(json.dumps([update], indent=2))

        # For every prefix announced by this origin
        for prefix in update["nlri"]:

            # Already detected
            if ((prefix, asOrigin) in detectedAttacks.keys()):
                count = detectedAttacks.get((prefix, asOrigin), 0)
                detectedAttacks[(prefix, asOrigin)] = count + 1

            # Check against db 
            else:
                prefixList = largerPrefixes(prefix)

                # a different origin 
                # the same or longer version of this prefix 
                query = {"as_origin": {"$ne": asOrigin}, "nlri": {"$in": prefixList}}
                # print(query)
                findResults = bgpcollection.find(query)

                for announcement in findResults:
                    printAttackInfo(update, prefix, announcement)



"""
Prints the information related to the attack
"""
def largerPrefixes(addressPrefix):

    pathSplit = addressPrefix.split('/')

    address = pathSplit[0]
    prefixLength = int(pathSplit[1])

    prefixes = [addressPrefix]
    
    # IPv4
    if type(ip_address(address)) is IPv4Address:
        for newPrefix in range (16, prefixLength):
            supernet = ip_network(addressPrefix).supernet(new_prefix=newPrefix)   
            prefixes.append(str(supernet))
        
    else: # "AFI_IPv6"
        # TODO!
        prefixes = [addressPrefix]


    return prefixes


"""
Prints the information related to the attack
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
    
    # Connect to database
    # TODO could add diff collections for the diff days we're examining 
    # Note is expected that the loader has been run first
    db = mongoConnect("bgpdata")
    bgpcollection = db["bgpdata"]

    # Where the update files are stored
    updateFileDirectory = sys.argv[1]

    # Start timer
    tic = time.perf_counter()
    
    # Process updates
    updateCount = processUpdateFiles(updateFileDirectory)

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

