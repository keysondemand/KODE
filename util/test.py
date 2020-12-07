import sys, re  
sys.path += ['./','../']

#from charm.toolbox.ecgroup   import ECGroup, ZR, G
from conf.groupparam         import *

g = group.random(G)
h = group.random(G)

def deserializeElements(objects):
    object_byte_strings = re.findall(r"'(.*?)'", objects , re.DOTALL)
    object_strings  = [ str.encode(a) for a in object_byte_strings]
    elements = [group.deserialize(a) for a in object_strings]
    return elements


def nizkpok_vec(dlog_commits, pedersen_commits, RHO, RHO_dash):
    # Importing g and h from common parameters now 
    #g = group.encode(decoded_g, True)
    #h = group.encode(decoded_h, True)
    #g = group.encode(decoded_g)
    #h = group.encode(decoded_h)

    pi_vec = []
    
    neworder = int(group.order()) // 4 # Cofactor of 4, ZR actual order is /4
    #for i in range(len(dlog_commits)):
    for i in range(1):
        v1 , v2 = group.random(ZR) % neworder , group.random(ZR) % neworder  
        #v1 , v2 = group.random(ZR) , group.random(ZR) 
        V1 = g ** v1 
        V2 = h ** v2 

        c = group.hash((g,h, dlog_commits[i], pedersen_commits[i],V1, V2), ZR) #TODO: Add commits to the hash 

        u1 = v1 - (c * RHO[i])
        u2 = v2 - (c * RHO_dash[i])
        #print("\n\nc:",c, "dlog_commit:", dlog_commits[i], "pedersen_commit:", pedersen_commits[i], "V1:", V1, "V2", V2)
        

        dlog_commit_inv = dlog_commits[i] ** (-1)


        V1_dash = (g ** u1) * (dlog_commits[i] ** c)
        V2_dash = (h ** u2) * ((pedersen_commits[i] /dlog_commits[i]) ** c)
        V2_ddash = (h ** u2) * ((pedersen_commits[i] * dlog_commit_inv) ** c)

        '''
        print("g:", g)
        print("h:", h)
        print("[c, u1, u2]:", [c, u1, u2])
        print("dlog:", dlog_commits[i])
        print("peder:", pedersen_commits[i])
        print("V1_dash:", V1_dash)
        print("V2_ddash:", V2_ddash)
        print("\n")
        c_dash = group.hash((g,h, dlog_commits[i], pedersen_commits[i],V1_dash, V2_ddash), ZR) 
        print("Inside")
        print("c", c)
        print("c_dash", c_dash)
        '''

        print("test_in:", group.hash((g,h), ZR))
        print(group.hash((g,h), ZR))



        #serialized_proof = [group.decode(c), group.decode(u1), group.decode(u2)]
        serialized_proof = [group.serialize(c), group.serialize(u1), group.serialize(u2)]
        #print("\nSender side proof:", [c, u1, u2])
        pi_vec.append(serialized_proof)

    return pi_vec, [c, u1, u2]




if __name__ == "__main__":
    neworder = int(group.order()) // 4 # Cofactor of 4, ZR actual order is /4

    s = group.random(ZR) % neworder
    r = group.random(ZR) % neworder 

    dlog_commit = g ** s 
    pedersen_commit = (g ** s) * (h ** r)

    proof, valproof = nizkpok_vec ([dlog_commit], [pedersen_commit], [s], [r] )
    '''
    proof = proof[0]
    proof = [group.deserialize(x) for x in proof]

    if proof == valproof:
        print("Equal")
    else:
        print("Not Equal")


    #[c, u1, u2] = proof 
    [c, u1, u2] = valproof 

    V1_dash = (g ** u1) * (dlog_commit ** c)
    dlog_commit_inv = dlog_commit ** (-1)
    V2_dash = (h ** u2) * ((pedersen_commit * dlog_commit_inv) ** c)

    #c_tilde = group.hash((g,h, dlog_commit, pedersen_commit,V1_dash, V2_dash), ZR) 
    c_tilde = group.hash((g,h, dlog_commit, pedersen_commit,V1_dash, V2_dash), ZR) 
    print("\n\n outside")

    print("g:", g)
    print("h:", h)

    print("[c, u1, u2]:", [c, u1, u2])

    print("dlog:", dlog_commit)
    print("peder:", pedersen_commit)
    print("V1_dash:", V1_dash)
    
    print("V2_dash:", V2_dash)

    print("c_dash")
    print( c_tilde)
    '''

    print("test_out :", group.hash((g,h), ZR))
    print(group.hash((g,h), ZR))




