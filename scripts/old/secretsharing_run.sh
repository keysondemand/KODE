#!/bin/bash

for NODES in `seq 4 15`
do
    for i in `seq 0 20`;
    do
        #echo $NODES
        #cd /Users/easwarvivek/Desktop/KODE/secretsharing/blackbox
        #python3 bbss.py -n $NODES
        cd /Users/easwarvivek/Desktop/KODE/secretsharing/combinatorial
        python3 css.py -n $NODES
        cd /Users/easwarvivek/Desktop/KODE/secretsharing/shamir
        python3 shamirsharing.py -n $NODES
    done 
done

#do script "cd /Users/easwarvivek/OneDrive\\ -\\ purdue.edu/work/rwork/LISS_DKG/DKG;py bbss_node.py -i '$i' -n '$NODES'"
#NODES=$1

#osascript -e 'tell app "Terminal" 
#    repeat 50 times
#        do script "cd /Users/easwarvivek/Desktop/KODE/secretsharing/combinatorial; py css.py  -n '$NODES'"
#        do script "cd /Users/easwarvivek/Desktop/KODE/secretsharing/shamir; py shamirsharing.py  -n '$NODES'"
#    end repeat
#end tell'
