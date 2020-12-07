import os, sys, math, json, re
from charm.toolbox.ecgroup      import ECGroup, ZR, G
from charm.toolbox.eccurve      import secp256k1, prime192v1,prime192v2
from charm.core.math.integer    import randomBits
from charm.core.math.integer import *

group = ECGroup(prime192v1)
group2 = ECGroup(prime192v1)
#TODO: This wrong, just for testing

bits = 192
q = randomPrime(bits,1)
p = randomPrime(bits-2, 1)
g = group.random(G)
h = group.random(G)

g2 = group2.random(G)
pqratio = p/q

#TODO: This wrong, just for testing

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




def partial_eval(nid, X, keytype ):
    global p, q
    keyfilename = "./tmp/node" + str(nid) + "share.txt"
    f = open(keyfilename)
    keystrings = f.readlines()
    keystrings = keystrings[0]
    elements = deserializeElements(keystrings)

    evaluations = []
    for i in range(len(elements)):
        X = X+str(i)
        H = group.hash(X, target_type=ZR)
        evaluations.append(H * elements[i])
    dot_prod = sum(evaluations)
    print(dot_prod)    
   
    #######################################
    val = int(dot_prod)*pqratio 
    print(val)
    #######################################

    par_sk = group.init(ZR,int(val))
    
    if keytype == "pub":
        global g
        partial_pk  = g** par_sk
        return partial_pk
    return par_sk
    


def partialEvalWithZKP(nid, X, keytype ):
    global p, q
    keyfilename = "./tmp/node" + str(nid) + "share.txt"
    f = open(keyfilename)
    keystrings = f.readlines()
    keystrings = keystrings[0]
    elements = deserializeElements(keystrings)

    evaluations = []
    for i in range(len(elements)):
        X = X+str(i)
        H = group.hash(X, target_type=ZR)
        evaluations.append(H * elements[i])
    dot_prod = sum(evaluations)
    print(dot_prod)    
   
    #######################################
    val = int(dot_prod)*pqratio 
    print(val)

    valTilde = int(dot_prod) % pqratio 
    #######################################


    par_sk = group.init(ZR,int(val))
    
    if keytype == "pub":
        global g
        partial_pk  = g** par_sk
        zkp = nizkEqualityOfBase(par_sk, g**par_sk, g2**par_sk, g, g2 )
        return partial_pk, zkp 

    return par_sk


if __name__=="__main__":
    keytype = "pub"
    partial_eval(0,"x", keytype)

