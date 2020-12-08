# KODE 

Protocol to generate secret keys on-the-fly

Requires:

Charm crypto library: https://github.com/JHUISI/charm
Tendermint: https://tendermint.com/ 

To test the code locally:

Install Tendermint
Run tendermint with kvstore app using `tendermint node --proxy_app=kvstore`

First check secret sharing:
Navigate to secretsharing/blackbox/ and run python3 bbss.py.
It runs a black-box secret sharing for a default of 4 nodes. 
For any other number of nodes, try `python3 bbss.py -n <number of nodes>`

Then navigate to scripts:
Run `sh bbss_dkg_run.sh <number of nodes>`
