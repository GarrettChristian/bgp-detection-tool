"""
Adapted from https://github.com/t2mune/mrtparse/blob/master/examples/mrt2bgpdump.py
"""

import sys, argparse, copy
from datetime import *
from mrtparse import *
import json
import uuid


def parse_args():
    p = argparse.ArgumentParser(
        description='This script converts to bgpdump format.')
    p.add_argument(
        '-m', dest='verbose', default=False, action='store_true',
        help='one-line per entry with unix timestamps')
    p.add_argument(
        '-M', dest='verbose', action='store_false',
        help='one-line per entry with human readable timestamps(default format)')
    p.add_argument(
        '-O', dest='output', default=sys.stdout, nargs='?', metavar='file',
        type=argparse.FileType('w'),
        help='output to a specified file')
    p.add_argument(
        '-s', dest='output', action='store_const', const=sys.stdout,
        help='output to STDOUT(default output)')
    p.add_argument(
        '-v', dest='output', action='store_const', const=sys.stderr,
        help='output to STDERR')
    p.add_argument(
        '-t', dest='ts_format', default='dump', choices=['dump', 'change'],
        help='timestamps for RIB dumps reflect the time of the dump \
            or the last route modification(default: dump)')
    p.add_argument(
        '-p', dest='pkt_num', default=False, action='store_true',
        help='show packet index at second position')
    p.add_argument(
        '-print', dest="print", default=False, action='store_true',
        help='Print the data')
    p.add_argument(
        'path_to_file',
        help='specify path to MRT format file')
    return p.parse_args()


class BgpDump:
    __slots__ = [
        'verbose', 'output', 'ts_format', 'pkt_num', 'type', 'num', 'ts',
        'org_time', 'flag', 'peer_ip', 'peer_as', 'nlri', 'withdrawn',
        'as_path', 'origin', 'next_hop', 'local_pref', 'med', 'comm', 'comm_list',
        'atomic_aggr', 'aggr', 'as4_path', 'as4_aggr', 'old_state', 'new_state', 
        'print', 'subtype', 'subtypeNum',
    ]

    def __init__(self, args):
        self.verbose = args.verbose
        self.output = args.output
        self.ts_format = args.ts_format
        self.pkt_num = args.pkt_num
        self.type = ''
        self.num = 0
        self.ts = 0
        self.org_time = 0
        self.flag = ''
        self.peer_ip = ''
        self.peer_as = 0
        self.nlri = []
        self.withdrawn = []
        self.as_path = []
        self.origin = ''
        self.next_hop = []
        self.local_pref = 0
        self.med = 0
        self.comm = ''
        self.comm_list = []
        self.atomic_aggr = 'NAG'
        self.aggr = ''
        self.as4_path = []
        self.as4_aggr = ''
        self.old_state = 0
        self.new_state = 0
        self.print = args.print
        self.subtype = ''
        self.subtypeNum = 0

    def print_line(self, prefix, next_hop):
        if self.ts_format == 'dump':
            d = self.ts
        else:
            d = self.org_time

        if self.verbose:
            d = str(d)

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
            if (self.print):    
                self.print_line(withdrawn, '')
        for nlri in self.nlri:
            if self.type == 'BGP4MP':
                self.flag = 'A'
            for next_hop in self.next_hop:
                if (self.print):
                    self.print_line(nlri, next_hop)

    # def td_toDict(self, m, count):
    #     data = {}
    #     data["type"] = 'TABLE_DUMP'
    #     data["flag"] = 'B'
    #     data["timestamp"] = list(m['timestamp'])[0]
    #     data["num"] = count
    #     data["originated_time"] = list(m['originated_time'])[0]
    #     data["peer_ip"] = m['peer_ip']
    #     data["peer_as"] = m['peer_as']
    #     data["prefix"] = m['prefix']
    #     data["prefix_length"] = m['prefix_length']
    #     path_attributes = []
    #     for attr in m['path_attributes']:
    #         path_attributes.append(attr)
    #     data["path_attributes"] = path_attributes
    #     return data

    def td_subtype(self, m):
        self.subtypeNum = list(m['subtype'])[0]
        if (self.subtypeNum == 1):
            self.subtype = "AFI_IPv4"
        elif (self.subtypeNum == 2):
            self.subtype = "AFI_IPv6"
        else:
            self.subtype = "TD_UNKNOWN"

    def td(self, m, count):
        self.type = 'TABLE_DUMP'
        self.flag = 'B'
        self.ts = list(m['timestamp'])[0]
        self.num = count
        self.org_time = list(m['originated_time'])[0]
        self.peer_ip = m['peer_ip']
        self.peer_as = m['peer_as']
        self.td_subtype(m)
        self.nlri.append('%s/%d' % (m['prefix'], m['prefix_length']))
        for attr in m['path_attributes']:
            self.bgp_attr(attr)
        if (self.print):
            self.print_routes()

    def td_v2_subtype(self, st):
        self.subtypeNum = st
        if (TD_V2_ST['PEER_INDEX_TABLE']):
            self.subtype = "PEER_INDEX_TABLE"
        elif (st == TD_V2_ST['RIB_IPV4_UNICAST']):
            self.subtype = "RIB_IPV4_UNICAST"
        elif (st == TD_V2_ST['RIB_IPV4_MULTICAST']):
            self.subtype = "RIB_IPV4_MULTICAST"
        elif (st == TD_V2_ST['RIB_IPV6_UNICAST']):
            self.subtype = "RIB_IPV6_UNICAST"
        elif (st == TD_V2_ST['RIB_IPV6_MULTICAST']):
            self.subtype = "RIB_IPV6_MULTICAST"
        elif (st == 6):
            self.subtype = "RIB_GENERIC"
        elif (st == 8):
            self.subtype = "RIB_IPV4_UNICAST_ADDPATH"
        elif (st == 9):
            self.subtype = "RIB_IPV4_MULTICAST_ADDPATH"
        elif (st == 10):
            self.subtype = "RIB_IPV6_UNICAST_ADDPATH"
        elif (st == 11):
            self.subtype = "RIB_IPV6_MULTICAST_ADDPATH"
        elif (st == 12):
            self.subtype = "RIB_GENERIC_ADDPATH"
        else:
            self.subtype = "TD_V2_ST_UNKNOWN"


    def td_v2(self, m):
        global peer
        self.type = 'TABLE_DUMP2'
        self.flag = 'B'
        self.ts = list(m['timestamp'])[0]
        st = list(m['subtype'])[0]
        self.td_v2_subtype(st)
        if st == TD_V2_ST['PEER_INDEX_TABLE']:
            peer = copy.copy(m['peer_entries'])
        elif (st == TD_V2_ST['RIB_IPV4_UNICAST']
            or st == TD_V2_ST['RIB_IPV4_MULTICAST']
            or st == TD_V2_ST['RIB_IPV6_UNICAST']
            or st == TD_V2_ST['RIB_IPV6_MULTICAST']):
            self.num = m['sequence_number']
            self.nlri.append('%s/%d' % (m['prefix'], m['prefix_length']))
            for entry in m['rib_entries']:
                self.org_time = list(entry['originated_time'])[0]
                self.peer_ip = peer[entry['peer_index']]['peer_ip']
                self.peer_as = peer[entry['peer_index']]['peer_as']
                self.as_path = []
                self.origin = ''
                self.next_hop = []
                self.local_pref = 0
                self.med = 0
                self.comm = ''
                self.atomic_aggr = 'NAG'
                self.aggr = ''
                self.as4_path = []
                self.as4_aggr = ''
                for attr in entry['path_attributes']:
                    self.bgp_attr(attr)
                if (self.print):
                    self.print_routes()

    def bgp4mp_subtype(self, st):
        self.subtypeNum = st
        if (st == BGP4MP_ST['BGP4MP_STATE_CHANGE']):
            self.subtype = "BGP4MP_STATE_CHANGE"
        elif (st == BGP4MP_ST['BGP4MP_STATE_CHANGE_AS4']):
            self.subtype = "BGP4MP_STATE_CHANGE_AS4"
        elif (st == BGP4MP_ST['BGP4MP_MESSAGE']):
            self.subtype = "BGP4MP_MESSAGE"
        elif (st == BGP4MP_ST['BGP4MP_MESSAGE_AS4']):
            self.subtype = "BGP4MP_MESSAGE_AS4"
        elif (st == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL']):
            self.subtype = "BGP4MP_MESSAGE_LOCAL"
        elif (st == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']):
            self.subtype = "BGP4MP_MESSAGE_AS4_LOCAL"
        elif (st == 8):
            self.subtype = "BGP4MP_MESSAGE_ADDPATH"
        elif (st == 9):
            self.subtype = "BGP4MP_MESSAGE_AS4_ADDPATH"
        elif (st == 10):
            self.subtype = "BGP4MP_MESSAGE_LOCAL_ADDPATH"
        elif (st == 11):
            self.subtype = "BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH"
        else:
            self.subtype = "BGP4MP_UNKNOWN"

    def bgp4mp(self, m, count):
        self.type = 'BGP4MP'
        self.ts = list(m['timestamp'])[0]
        self.num = count
        self.org_time = list(m['timestamp'])[0]
        self.peer_ip = m['peer_ip']
        self.peer_as = m['peer_as']
        st = list(m['subtype'])[0]
        self.bgp4mp_subtype(st)
        if (st == BGP4MP_ST['BGP4MP_STATE_CHANGE']
            or st == BGP4MP_ST['BGP4MP_STATE_CHANGE_AS4']):
            self.flag = 'STATE'
            self.old_state = list(m['old_state'])[0]
            self.new_state = list(m['new_state'])[0]
            if (self.print):
                self.print_line([], '')
        elif (st == BGP4MP_ST['BGP4MP_MESSAGE']
            or st == BGP4MP_ST['BGP4MP_MESSAGE_AS4']
            or st == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL']
            or st == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']):
            if list(m['bgp_message']['type'])[0] != BGP_MSG_T['UPDATE']:
                return
            for attr in m['bgp_message']['path_attributes']:
                self.bgp_attr(attr)
            for withdrawn in m['bgp_message']['withdrawn_routes']:
                self.withdrawn.append(
                    '%s/%d' % (
                        withdrawn['prefix'], withdrawn['prefix_length']
                    )
                )
            for nlri in m['bgp_message']['nlri']:
                self.nlri.append(
                    '%s/%d' % (
                        nlri['prefix'], nlri['prefix_length']
                    )
                )
            if (self.print):
                self.print_routes()

    def bgp_attr(self, attr):
        attr_t = list(attr['type'])[0]
        if attr_t == BGP_ATTR_T['ORIGIN']:
            self.origin = ORIGIN_T[list(attr['value'])[0]]
        elif attr_t == BGP_ATTR_T['NEXT_HOP']:
            self.next_hop.append(attr['value'])
        elif attr_t == BGP_ATTR_T['AS_PATH']:
            self.as_path = []
            for seg in attr['value']:
                seg_t = list(seg['type'])[0]
                if seg_t == AS_PATH_SEG_T['AS_SET']:
                    self.as_path.append('{%s}' % ','.join(seg['value']))
                elif seg_t == AS_PATH_SEG_T['AS_CONFED_SEQUENCE']:
                    self.as_path.append('(' + seg['value'][0])
                    self.as_path += seg['value'][1:-1]
                    self.as_path.append(seg['value'][-1] + ')')
                elif seg_t == AS_PATH_SEG_T['AS_CONFED_SET']:
                    self.as_path.append('[%s]' % ','.join(seg['value']))
                else:
                    self.as_path += seg['value']
        elif attr_t == BGP_ATTR_T['MULTI_EXIT_DISC']:
            self.med = attr['value']
        elif attr_t == BGP_ATTR_T['LOCAL_PREF']:
            self.local_pref = attr['value']
        elif attr_t == BGP_ATTR_T['ATOMIC_AGGREGATE']:
            self.atomic_aggr = 'AG'
        elif attr_t == BGP_ATTR_T['AGGREGATOR']:
            self.aggr = '%s %s' % (attr['value']['as'], attr['value']['id'])
        elif attr_t == BGP_ATTR_T['COMMUNITY']:
            self.comm = ' '.join(attr['value'])
            self.comm_list = attr['value']
        elif attr_t == BGP_ATTR_T['MP_REACH_NLRI']:
            self.next_hop = attr['value']['next_hop']
            if self.type != 'BGP4MP':
                return
            for nlri in attr['value']['nlri']:
                self.nlri.append(
                    '%s/%d' % (
                        nlri['prefix'], nlri['prefix_length']
                    )
                )
        elif attr_t == BGP_ATTR_T['MP_UNREACH_NLRI']:
            if self.type != 'BGP4MP':
                return
            for withdrawn in attr['value']['withdrawn_routes']:
                self.withdrawn.append(
                    '%s/%d' % (
                        withdrawn['prefix'], withdrawn['prefix_length']
                    )
                )
        elif attr_t == BGP_ATTR_T['AS4_PATH']:
            self.as4_path = []
            seg_t = list(seg['type'])[0]
            for seg in attr['value']:
                if seg_t == AS_PATH_SEG_T['AS_SET']:
                    self.as4_path.append('{%s}' % ','.join(seg['value']))
                elif seg_t == AS_PATH_SEG_T['AS_CONFED_SEQUENCE']:
                    self.as4_path.append('(' + seg['value'][0])
                    self.as4_path += seg['value'][1:-1]
                    self.as4_path.append(seg['value'][-1] + ')')
                elif seg_t == AS_PATH_SEG_T['AS_CONFED_SET']:
                    self.as4_path.append('[%s]' % ','.join(seg['value']))
                else:
                    self.as4_path += seg['value']
        elif attr_t == BGP_ATTR_T['AS4_AGGREGATOR']:
            self.as4_aggr = '%s %s' % (
                attr['value']['as'], attr['value']['id']
            )

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

    def toDict(self):
        data = {}
        data["_id"] = str(uuid.uuid4())
        data["type"] = self.type
        data["num"] = self.num
        data["timestamp"] = self.ts
        data["originated_time"] = self.org_time
        data["flag"] = self.flag
        data["peer_ip"] = self.peer_ip
        data["peer_as"] = self.peer_as
        data["nlri"] = self.nlri
        data["withdrawn"] = self.withdrawn
        data["as_path"] = self.as_path
        data["origin"] = self.origin
        data["next_hop"] = self.next_hop
        data["local_pref"] = self.local_pref
        data["med"] = self.med
        data["communities"] = self.comm_list
        data["atomic_aggr"] = self.atomic_aggr
        data["aggr"] = self.aggr
        data["as4_path"] = self.as4_path
        data["as4_aggr"] = self.as4_aggr
        data["old_state"] = self.old_state
        data["new_state"] = self.new_state
        data['subtype'] = self.subtype
        data['subtype_num'] = self.subtypeNum

        return data

    def toDictSelect(self):
        data = {}
        data["_id"] = str(uuid.uuid4())
        data["type"] = self.type
        data["num"] = self.num
        data["timestamp"] = self.ts
        data["originated_time"] = self.org_time
        data["flag"] = self.flag
        data["peer_ip"] = self.peer_ip
        data["peer_as"] = self.peer_as
        data["nlri"] = self.nlri
        data["withdrawn"] = self.withdrawn
        data["as_path"] = self.as_path
        if (len(self.as_path) > 0):
            data["as_origin"] = self.as_path[-1]
        data["origin"] = self.origin
        data["next_hop"] = self.next_hop
        data["local_pref"] = self.local_pref
        data["med"] = self.med
        data["communities"] = self.comm_list
        data["atomic_aggr"] = self.atomic_aggr
        data["aggr"] = self.aggr
        data["as4_path"] = self.as4_path
        data["as4_aggr"] = self.as4_aggr
        data["old_state"] = self.old_state
        data["new_state"] = self.new_state
        data['subtype'] = self.subtype
        data['subtype_num'] = self.subtypeNum

        return data

def parseData(m, args, count):
    b = BgpDump(args)
    t = list(m.data['type'])[0]
    if t == MRT_T['TABLE_DUMP']:
        b.td(m.data, count)
    elif t == MRT_T['TABLE_DUMP_V2']:
        b.td_v2(m.data)
    elif t == MRT_T['BGP4MP']:
        b.bgp4mp(m.data, count)

    return b.toDictSelect()

def main():
    args = parse_args()
    d = Reader(args.path_to_file)
    count = 0
    for m in d:
        if m.err:
            continue
        b = BgpDump(args)
        t = list(m.data['type'])[0]
        if t == MRT_T['TABLE_DUMP']:
            b.td(m.data, count)
        elif t == MRT_T['TABLE_DUMP_V2']:
            b.td_v2(m.data)
        elif t == MRT_T['BGP4MP']:
            b.bgp4mp(m.data, count)
        count += 1
        
        
        item = b.toDict()
        if args.print:
            print(json.dumps([item], indent=2))

        if count == 100:
            break

if __name__ == '__main__':
    main()
