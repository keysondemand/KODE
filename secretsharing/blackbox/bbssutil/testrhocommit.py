import sys  
sys.path += ['./','../', '../../', '../../../']

import numpy as np 
#from charm.toolbox.ecgroup   import ECGroup, ZR, G

from conf.groupparam             import *
from secretsharing.blackbox.bbss import *

def rhoCommit(M, malicious=0):

    S, RHO           = bbssShareGen4DKG(M) #RHO[0] is the random secret 
    S_dash, RHO_dash = bbssShareGen4DKG(M) 

    rho_commits = []
    rho_commit_strings = []

    dlog_commits = []
    dlog_commit_strings = []

    # Importing g and h from common parameters now 
    #g = group.encode(decoded_g, True)
    #h = group.encode(decoded_h, True)
    g = group.encode(decoded_g)
    h = group.encode(decoded_h)

    for i in range(len(RHO)):
        commit_val = (g ** RHO[i]) * (h ** RHO_dash[i])
        dlog_commit_val = (g ** RHO[i]) 

        if malicious:
            commit_val = group.random(G)
            dlog_commit_val = group.random(G)
        rho_commits.append(commit_val)
        rho_commit_strings.append(group.serialize(commit_val))

        dlog_commits.append(dlog_commit_val)
        dlog_commit_strings.append(group.serialize(dlog_commit_val))
    return S, S_dash, rho_commits , rho_commit_strings,  RHO, RHO_dash, dlog_commits, dlog_commit_strings


def rhoCommitPSS(M, share, share_dash):

    if debug:
        print("share and share_dash in rhoCommitPSS:", share, share_dash)

    S, RHO           = bbssShareGen4PSS(M, share) #RHO[0] is the random secret 
    S_dash, RHO_dash = bbssShareGen4PSS(M, share_dash) 

    rho_commits = []
    rho_commit_strings = []

    dlog_commits = []
    dlog_commit_strings = []

    # Importing g and h from common parameters now 
    #g = group.encode(decoded_g, True)
    #h = group.encode(decoded_h, True)
    g = group.encode(decoded_g)
    h = group.encode(decoded_h)

    for i in range(len(RHO)):
        commit_val = (g ** RHO[i]) * (h ** RHO_dash[i])

        dlog_commit_val = (g ** RHO[i]) 

        rho_commits.append(commit_val)
        rho_commit_strings.append(group.serialize(commit_val))

        dlog_commits.append(dlog_commit_val)
        dlog_commit_strings.append(group.serialize(dlog_commit_val))
    return S, S_dash, rho_commits , rho_commit_strings,  RHO, RHO_dash, dlog_commits, dlog_commit_strings


if __name__ == "__main__":
    M = np.loadtxt("M.txt", dtype=int)
    M = np.array(M)
    print("M:", M)
    #print(rhoCommit(M))

    print("group:", group)

    g = group.encode(decoded_g)
    h = group.encode(decoded_h)

    g_rand = group.random(G)
    zero = group.init(ZR, int(0))
    eight = group.init(ZR, int(8))

    S, S_dash, rho_commits , rho_commit_strings,  RHO, RHO_dash, dlog_commits, dlog_commit_strings = rhoCommit(M)

    Verified = []
    NotVerified = []
    for i in range(len(S)):

        computed_share_commitment = (g ** S[i]) * ( h ** S_dash[i])
        commitment_product = (g_rand ** eight) ** zero
        print("unity:", commitment_product)

        for j in range(len(M[i])):
            print("M[i][j]:", M[i][j])
            if M[i][j] == 1:
                b = group.init(ZR, int(M[i][j]))
                commitment_product = commitment_product * (rho_commits[j] ** b)
    
        print("computed_share_commitment:", computed_share_commitment, "\ncommitment_product", commitment_product)
        if (computed_share_commitment == commitment_product):
            Verified.append(i)
        else:
            NotVerified.append(i)

    print("Verified:", Verified)
    print("NotVerified:", NotVerified)


    g = group.random(G)

    a = group.random(ZR)
    b = group.random(ZR)

    c = a + b

    A = g ** a
    B = g ** b
    C1 = A * B
    C = g**c

    print("C1:", C1)
    print("C:", C)
    '''
    print("group:", group)
    
    for index in range(5):
        order = group.order()
        #print("order", order)
        neworder = int(order) // 4 
    
        #M = np.array([[1,1],[1,1]])
        M = np.loadtxt("M.txt", dtype=int)
        M = np.array(M)
        #print("M:", M)
        #print(M)
        #print("group:", group)
        g = group.encode(decoded_g)
        h = group.encode(decoded_h)
    
        #RHO       = [group.random(ZR), group.random(ZR)]
        #RHO_dash  = [group.random(ZR), group.random(ZR)]
    
        RHO      = [group.random(ZR) for i in range(len(M[0]))]
        RHO_dash = [group.random(ZR) for i in range(len(M[0]))]
    
    
        SHARE         = M.dot(RHO)
        SHARE_dash    = M.dot(RHO_dash)
    
        R       = [group.random(ZR) % neworder for i in range(len(M[0]))]
        R_dash       = [group.random(ZR) % neworder for i in range(len(M[0]))]
    
        S      = M.dot(R)
        S_dash = M.dot(R_dash)
    
    
        commits = []
        C = []
        for i in range(len(RHO)):
            commit = (g ** RHO[i]) * (h ** RHO_dash[i])
            c      = (g ** R[i] )  * (h ** R_dash[i])
     
            commits.append(commit)
            C.append(c)
    
        ####### check the commits now 
    
        g_rand = group.random(G)
        zero = group.init(ZR, int(0))
        eight = group.init(ZR, int(8))
    
    
        Verified = []
        NotVerified = []
    
        V = []
        NV = []
        for i in range(len(S)):
    
            computed_share_commitment = (g ** SHARE[i]) * ( h ** SHARE_dash[i])
            csc = (g ** S[i]) * (h ** S_dash[i])
    
            commitment_product = (g_rand ) ** zero
            cp                 = (g_rand ) ** zero
            #print("unity:", commitment_product)
    
            for j in range(len(M[i])):
                #print("M[i][j]:", M[i][j])
                if M[i][j] == 1:
                    b = group.init(ZR, int(M[i][j]))
                    commitment_product = commitment_product * (commits[j] ** b)
                    cp = cp * (C[j] ** b) 
    
            #print("computed_share_commitment:", computed_share_commitment, "\ncommitment_product", commitment_product)
            if (computed_share_commitment == commitment_product):
                Verified.append(i)
            else:
                NotVerified.append(i)
    
            if (csc == cp):
                V.append(i)
            else:
                NV.append(i)
    
    
        print("Verified:", Verified)
        print("NotVerified:", NotVerified)
        print("V:", V)
        print("NV:", NV)

    if group == group283 or group == group571:
        print("Yes")
    '''
