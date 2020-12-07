import os, sys, math, json, re, time 

from charm.toolbox.ecgroup      import ECGroup, ZR, G
from charm.toolbox.eccurve      import secp256k1, prime192v1,prime192v2
from charm.core.math.integer    import randomBits
from charm.core.math.integer    import *

import numpy as np 

sys.path += ['./','../']

from conf.groupparam  import * 
from decimal import *

#group is whatever DKG has been performed on 

#p = group256.order()
q = group.order()
#q = group160.order()
p = 3934245467 #32 bit prime 

#q = group160.order()
q1 = group256.order()



getcontext().prec = 160

pqratio = Decimal(int(p)) / Decimal(int(q))

#u is total number of DKG instances/shares 
#u = 512
u = 256
#u = 1024
'''
pbits = 256
qbits = 512 
float pqratio = p/q 
pqbitdiff = qbits - pbits 
pqration = 2 ** pqbitdiff 
'''


def deserializeElements(objects):
    object_byte_strings = re.findall(r"'(.*?)'", objects , re.DOTALL)
    object_strings  = [ str.encode(a) for a in object_byte_strings]
    elements = [group.deserialize(a) for a in object_strings]
    return elements

def partial_eval(nid, X, keytype):
    global p, q, u
    #keyfilename = "./tmp/node" + str(nid) + "share.txt"
    keyfilename = "./tmp/node" + str(nid) + "sharelist.txt"
    #keyfilename = "./tmp/node" + str(nid) + "share.txt"
    
    file_read_start = time.process_time()

    keystrings = []
    with open(keyfilename) as f:
        keystrings = [next(f) for x in range(u)]
    share_rows = []  #Holds u rows, each row indicates one 'share'

    file_read_end = time.process_time()

    print("file read time:", (file_read_end - file_read_start)*1000)
    
    for i in range(len(keystrings)):
        ele = deserializeElements(keystrings[0])
        #print(ele)
        share_rows.append(ele)
    #share size is number of elements 
    # we need u such share vectors 


    key_eval_start = time.process_time()

    print("len(share_rows[0])", len(share_rows[0]))
    par_eval = []
    for j in range(len(share_rows[0])):
        evaluations = []
        for i in range(u):
    #for i in range(len(elements)):
            X = X+str(i)
            H = group.hash(X, target_type=ZR)
            #evaluations.append(H * elements[i])
            evaluations.append(H * share_rows[i][j])
        dot_prod = sum(evaluations)

        ###############################################
        val = int(dot_prod) * pqratio    #Rounding down 
        ###############################################

        #Always output secp256k1 keys 
        par_sk = group256.init(ZR,int(val))


        #par_sk = group.init(ZR,int(val))
        par_eval.append(par_sk)

    key_eval_end = time.process_time()

    print("key eval time:", (key_eval_end - key_eval_start )*1000)
    #print("pr_eval:", par_eval) 

    if keytype == "pub":
        partial_pk  = [g256 ** x for x in par_eval] 
        #print("partial_pk:", partial_pk)
        return partial_pk
    elif keytype == "sec":
        return par_eval

if __name__=="__main__":
    keytype = "pub"
    partial_eval(0,"x", keytype)

