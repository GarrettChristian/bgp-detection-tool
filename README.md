# bgp-detection-tool
bgp-detection-tool for the network security group project

### Usage guide
- python3 dataLoader [path to rib file]
- python3 detectionTool 
- python3 dataFeeder [path to update file]

### System requirements detection tool
- python3
- pip install mrtparse
- python3 -m pip install pymongo
- python3 -m pip install "pymongo[srv]"

---

## RIS live demo

### Usage guide
- python3 risConnect.py

### System requirements ris
- python3
- pip3 install websocket-client
- Note, on mac I had to run the "Install Certificates.command" found where my python is installed


---

### postgres exploration
- pip install psycopg2
  - Note on mac first needed to: brew install postgres


