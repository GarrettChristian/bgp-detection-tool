# bgp-detection-tool
bgp-detection-tool for the network security group project

---

### Setting up your python environment
- install python3
  - sudo apt-get install python3-distutils python3-pip python3-dev python3-venv
  - on UVA resources module load python
- cd ~
- python3 -m venv netsec_venv
- source $HOME/netsec_venv/bin/activate
  - Note this will need to be run everytime you want to run the project
  - This can be added to your .bashrc / .zshrc file as an alias to make your life easier for example: alias netv='source $HOME/netsec_venv/bin/activate'
- pip install mrtparse
- python3 -m pip install pymongo
- python3 -m pip install "pymongo[srv]"

### Setting up the connection to mongodb
- add the txt file called mongoconnect.txt with one line that looks like mongodb://ipaddress:port/

---

### Usage guide
- The data loader should be run before the detection to tool to preload the randomly sampled prefixes we plan on tracking
- python3 dataLoader [rib_file] [mongo_collection]
  - rib_file          Path to the RIB file
  - mongo_collection  Mongo db collection name
- python3 detectionTool [update_directory] [mongo_collection]
- (see runScripts for examples)

---

## RIS live demo

### Usage guide
- python3 risConnect.py

### System requirements ris
- python3
- pip3 install websocket-client
- Note, on mac I had to run the "Install Certificates.command" found where my python is installed


---

## Mongo commands
- To remove everything from a collection
  - in compass console 
  - use bgdata
  - db.bgpdata.remove({})
    - Can replace bgpdata with the collection you'd like to remove from
- Remove specific batch
  - db.bgpTest.remove({batchId: {$ne: "a11fc9d2-fe90-4d69-abe4-daf16b142855"}})

---

## Other explorations

### postgres exploration
- pip install psycopg2
  - Note on mac first needed to: brew install postgres

### routinator connection
- pip install requests