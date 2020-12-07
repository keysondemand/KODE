import sys 

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../conf/')
from charm.toolbox.ecgroup import ECGroup, ZR, G


from conf.groupparam  import *

def nizkEqualityOfBase(exponent, valueBase1, valueBase2, g1, g2):
    
    v = group.random(ZR)

    # Commitment to random value 

    V1_exp = group256.init(ZR, int(v))
    V2_exp = group283.init(ZR, int(v))

    V1 = g1 ** V1_exp
    V2 = g2 ** V2_exp

    #hash 
    x = "something something"
    c = group.hash(x, target_type = ZR)

    #response 
    #u = v + (exponent * c) 

    serialized_proof = []
    #serialized_proof = [group.serialize(c), group.serialize(u), group.serialize(V1), group2.serialize(V2)]

    return serialized_proof 
