"""
https://www.mongodb.com/blog/post/getting-started-with-python-and-mongodb
"""

from os import times
from sqlite3 import Timestamp
from time import time
from pymongo import MongoClient
from mrtparse import *
import uuid

import json
from collections import namedtuple
from json import JSONEncoder

def mongoConnect():
    configFile = open("mongoconnect.txt", "r")
    mongoUrl = configFile.readline()
    print("Connecting to: ", mongoUrl)
    configFile.close()

    client = MongoClient(mongoUrl)
    db = client.bgpdata
    return db

def merge_as_path(self):
    if len(self.as4_path):
        n = len(self.as_path) - len(self.as4_path)
        return ' '.join(self.as_path[:n] + self.as4_path)
    else:
        return ' '.join(self.as_path)

def merge_aggr(self):
    if len(self.as4_aggr):
        return self.as4_aggr
    else:
        return self.aggr

def print_line(self, prefix, next_hop):
    if self.ts_format == 'dump':
        d = self.ts
    else:
        d = self.org_time

    if self.verbose:
        d = str(d)
    else:
        d = datetime.utcfromtimestamp(d).strftime('%m/%d/%y %H:%M:%S')

    if self.pkt_num == True:
        d = '%d|%s' % (self.num, d)

    if self.flag == 'B' or self.flag == 'A':
        self.output.write(
            '%s|%s|%s|%s|%s|%s|%s|%s' % (
                self.type, d, self.flag, self.peer_ip, self.peer_as, prefix,
                self.merge_as_path(), self.origin
            )
        )
        if self.verbose == True:
            self.output.write(
                '|%s|%d|%d|%s|%s|%s|\n' % (
                    next_hop, self.local_pref, self.med, self.comm,
                    self.atomic_aggr, self.merge_aggr()
                )
            )
        else:
            self.output.write('\n')
    elif self.flag == 'W':
        self.output.write(
            '%s|%s|%s|%s|%s|%s\n' % (
                self.type, d, self.flag, self.peer_ip, self.peer_as,
                prefix
            )
        )
    elif self.flag == 'STATE':
        self.output.write(
            '%s|%s|%s|%s|%s|%d|%d\n' % (
                self.type, d, self.flag, self.peer_ip, self.peer_as,
                self.old_state, self.new_state
            )
        )

def print_routes(self):
    for withdrawn in self.withdrawn:
        if self.type == 'BGP4MP':
            self.flag = 'W'
        self.print_line(withdrawn, '')
    for nlri in self.nlri:
        if self.type == 'BGP4MP':
            self.flag = 'A'
        for next_hop in self.next_hop:
            self.print_line(nlri, next_hop)

def td(self, m, count):
    self.type = 'TABLE_DUMP'
    self.flag = 'B'
    self.ts = list(m['timestamp'])[0]
    self.num = count
    self.org_time = list(m['originated_time'])[0]
    self.peer_ip = m['peer_ip']
    self.peer_as = m['peer_as']
    self.nlri.append('%s/%d' % (m['prefix'], m['prefix_length']))
    for attr in m['path_attributes']:
        self.bgp_attr(attr)
    self.print_routes()

def cleanData(data):
    print(data["timestamp"])
    # fix time stamp given as {"1203682387": "2008-02-22 07:13:07"}
    try:
        timestamp = list(data["timestamp"].keys())[0]
        date = data["timestamp"][timestamp]
        data["timestamp"] = timestamp
        data["date"] = date
    except:
        print("Couln't fix time stamp")


    # fix originated_time stamp given as {"1203682387": "2008-02-22 07:13:07"}
    try:
        originated_timestamp = list(data["originated_time"].keys())[0]
        originated_date = data["originated_time"][originated_timestamp]
        data["originated_time"] = originated_timestamp
        data["originated_date"] = originated_date
    except:
        print("Couln't fix originated_timestamp stamp")

    # Give the data a random uuid
    data["id"] = str(uuid.uuid4())

    print(json.dumps([data], indent=2)[2:-2])


def main():
    
    # db = mongoConnect()


    # insertData = {}
    

    sys.stdout.write('[\n')
    i = 0
    for entry in Reader(sys.argv[1]):
        if i != 0:
            sys.stdout.write(',\n')
        sys.stdout.write(json.dumps([entry.data], indent=2)[2:-2])

        # cleanData(entry.data)
        # insertData = entry.data
        
        # if (list(entry.data['type'])[0] != 12):
        #     print(entry.data['type'])
        
        i += 1
        if (i == 1):
            break
    sys.stdout.write('\n]\n')

    # result = db.bgpdata.insert_one(insertData)

if __name__ == '__main__':
    main()
