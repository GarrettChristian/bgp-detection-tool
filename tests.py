
import re


from detectionTool import getLargerPrefixes
from detectionTool import getSmallerPrefixes



def testPrefixHijack():
    googlePrefix = "208.65.152.0/22"
    hijackPrefix = "208.65.153.0/24"

    results = getLargerPrefixes(hijackPrefix)

    found = False
    for subnet in results:
        print(subnet)
        if (subnet == googlePrefix):
            found = True
    
    assert(found)


def main():
    testPrefixHijack()

    print("larger")
    print(getLargerPrefixes("208.65.153.0/24"))
    print("smaller")
    print(getSmallerPrefixes("208.65.153.0/24"))


if __name__ == '__main__':
    main()



