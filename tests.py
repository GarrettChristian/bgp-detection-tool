
import re


from detectionTool import largerPrefixes



def testPrefixHijack():
    googlePrefix = "208.65.152.0/22"
    hijackPrefix = "208.65.153.0/24"

    results = largerPrefixes(hijackPrefix, "AFI_IPv4")

    found = False
    for subnet in results:
        print(subnet)
        if (subnet == googlePrefix):
            found = True
    
    assert(found)


def main():
    testRegexPrefixHijack()


if __name__ == '__main__':
    main()



