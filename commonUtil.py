
"""
Common Helper Functions
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


"""
Connect to our mongodb collection
"""
def mongoConnect(database):
    configFile = open("mongoconnect.txt", "r")
    mongoUrl = configFile.readline()
    print("Connecting to: ", mongoUrl)
    configFile.close()

    client = MongoClient(mongoUrl)
    db = client[database]
    return db