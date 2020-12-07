import sys, re  
sys.path += ['./','../']

#from charm.toolbox.ecgroup   import ECGroup, ZR, G
from conf.groupparam         import *

neworder = int(group.order()) 

#g1 = g ** group.init(ZR, int(16))
#h1 = h ** group.init(ZR, int(16))

g1 = group.random(G)
h1 = group.random(G)

print("out out g1h1:", group.hash((g1,h1), ZR))

def nizkpok(g1, h1):


    print("g1", g1)
    print("h1", h1)

    g1h1_in = int(group.hash((g1,h1), ZR)) % neworder
    print("g1h1_in:", g1h1_in)

    g1h1str = str(g1h1_in)
    g1h1str = g1h1str[:len(g1h1str)-20]

    print("g1h1_in_str:",g1h1str)
    

    return g1, h1



if __name__ == "__main__":
    import pdb
    #pdb.set_trace()
    #global g1
    #global h1

    #g1 = group.random(G)
    #h1 = group.random(G)



    #g1 = g ** group.init(ZR, int(16))
    #h1 = h ** group.init(ZR, int(16))

    g2, h2 = nizkpok(g1, h1)

    print("\n")

    print("g1", g1)
    print("h1", h1)

    g1h1_out = int(group.hash((g1,h1), ZR)) % neworder 

    g1h1str = str(g1h1_out)
    g1h1str = g1h1str[:len(g1h1str)-20]

    print("g1h1_out:", g1h1_out)
    print("g1h1_out_str:", g1h1str)




