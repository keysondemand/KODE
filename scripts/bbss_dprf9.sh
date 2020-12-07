#!/bin/bash

NODES=$1

osascript -e 'tell app "Terminal" 
        do script "cd /Users/easwarvivek/Desktop/KODE/secretsharing/blackbox/; python3 bbss.py  -n '$NODES' "
    end tell'

for i in `seq 1 $NODES`;
do
    j=$(($i-1))
        osascript -e 'tell app "Terminal" 
            do script "cd /Users/easwarvivek/Desktop/KODE/DKG/bbss_dkg/; python3 dprf_bbssnode9.py -i '$j' -n '$NODES' -m 0"
        end tell'
done 
    
