
"""
https://pynative.com/python-convert-json-data-into-custom-python-object/
https://github.com/t2mune/mrtparse/blob/master/examples/mrt2json.py
"""
import json
import sys
from mrtparse import *

import json
from collections import namedtuple
from json import JSONEncoder


def main():
    sys.stdout.write('[\n')
    i = 0
    for entry in Reader(sys.argv[1]):
        if i != 0:
            sys.stdout.write(',\n')
        sys.stdout.write(json.dumps([entry.data], indent=2)[2:-2])
        i += 1
        if (i == 1):
            break
    sys.stdout.write('\n]\n')

if __name__ == '__main__':
    main()
