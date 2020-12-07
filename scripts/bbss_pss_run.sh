#!/bin/bash

NODES=$1

osascript -e 'tell app "Terminal" 
        do script "cd /Users/easwarvivek/Desktop/KODE/secretsharing/blackbox/; python3 bbss.py  -n '$NODES' "
    end tell'
THRESHOLD=$(($NODES/3))
NONMAL=$(($NODES-$THRESHOLD ))
echo Total Nodes:         $NODES
echo Threshold:           $THRESHOLD 
echo Non Malicious nodes: $NONMAL

for i in `seq 1 $NODES`;
do
    j=$(($i-1))
        osascript -e 'tell app "Terminal" 
            do script "cd /Users/easwarvivek/Desktop/KODE/PSS/bbss_pss/; python3 bbss_pssnode.py -i '$j' -n '$NODES' -m 0"
        end tell'
done 
    
#n=$(($1 - 1))
#
#for i in `seq 0 $n`;
#do
#    echo $NODES
#    osascript -e 'tell app "Terminal" 
#        do script "cd /Users/easwarvivek/Desktop/KODE/DKG/bbss_dkg/; python3 bbssnode.py -i '$i' -n '$NODES' -m 1"
#    end tell'
#done 

#do script "cd ../DKG/bbss_dkg/;python3 bbssnode.py -i '$i' -n '$NODES' -m 1"
#py /Users/easwarvivek/Desktop/KODE/secretsharing/blackbox/bbss.py -n $NODES
