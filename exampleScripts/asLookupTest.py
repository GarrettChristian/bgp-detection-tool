import pyasn

# Initialize module and load IP to ASN database
# the sample database can be downloaded or built - see below
asndb = pyasn.pyasn('ipasn_20140513.dat')

asndb.lookup('8.8.8.8')
# should return: (15169, '8.8.8.0/24'), the origin AS, and the BGP prefix it matches

asndb.get_as_prefixes(1128)
# returns ['130.161.0.0/16', '131.180.0.0/16', '145.94.0.0/16'], TU-Delft prefixes