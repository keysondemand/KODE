#!/bin/bash

NODES=$1


for i in `seq 1 $NODES`;
do
    j=$(($i-1))
        osascript -e 'tell app "Terminal" 
            do script "cd /Users/easwarvivek/Desktop/KODE/DKG/bbss_dkg/; python3 send_receive_hello.py  -i '$j' -n '$NODES' "
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
