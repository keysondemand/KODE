import secrets, math, json, sys, argparse, ast, time  
import numpy as np

sys.path += ['./', '../', '../../']

#import group parameters 
from conf.groupparam                                            import * 
from secretsharing.blackbox.bbssutil.checkiter                  import * 
from secretsharing.blackbox.bbssutil.distmatrix.dist_matrix_gen import *
from secretsharing.blackbox.bbssutil.distmatrix.maj_index_list  import * 


def DPRINT ( *args , **kwargs ) : 
    if debug:
        print ( *args , **kwargs )

debug = 0

def searchNMmap(n,m):
    #  Searches for a good random instance of input literals (n) to leaves (m) map: N_M_map
    #  Assigns to each node what leaf index it has obtained 
    randomized_input_indices = []       # y literals after mapping from x
    N_M_map = {x: [] for x in range(n)} # the mapping from x(input index) to y(leaf index). Each x has different positions to which it is mapped to 
    no_of_shares_ratio = math.floor(m/n)

    if n < 15:
        DPRINT("Searching for a good N_M_map ...")
        while any(len(x)< no_of_shares_ratio for x in N_M_map.values()):    
        #while any(len(x)<= (m/(2*n)) for x in N_M_map.values()):    
        #while any(len(x) == 0 for x in N_M_map.values()):    
            N_M_map = {k: [] for k in range(n)} 
            randomized_input_indices = []       
            for i in range(m):
                r = secrets.randbelow(n)        # Uniform random position for each x to go to. Change this?   
                randomized_input_indices.append(r)
                N_M_map[r].append(i)
        DPRINT("N_M_map:", N_M_map)    
        DPRINT("Generated literals")    
    else:
        # For n > 20
        DPRINT("Searching for a good N_M_map ...")
        while any(len(x)< no_of_shares_ratio for x in N_M_map.values()):   
            randomized_input_indices = []       
            already_selected = []
            for i in range(m):
                r = secrets.randbelow(n)        # Uniform random position for each x to go to. 
                if i < n: 
                    while(r in already_selected):  #dont choose the index if already selected - use for (27,27) etc 
                        r = secrets.randbelow(n)        
                    already_selected.append(r)
                randomized_input_indices.append(r)
                N_M_map[r].append(i)
            DPRINT("N_M_map:", N_M_map)    
    return randomized_input_indices, N_M_map


def generateLiterals(n):
    # 1.  computes the number of leaves required for the threshold circuit
    # 2.  Searches for a good random instance of input literals (n) to leaves (m) map: N_M_map
    # 3.  Assigns to each node what leaf index it has obtained 
    # For higher n, we do not need delta = 1/n, we can do lot better with smaller delta 

    start_p = 0.66  # This is for n/3 crash nodes 
    delta   = 1/n   # This is always 1/n?    Changes for n > 15 

    m = 3** (number_iter(start_p, delta, n))

    DPRINT("To reach the requried probability, calculated m:", m, "n:", n)


    if m < n:         # Choose the closest power of 3 greater than n
        print(" m < n, so choosing the next power of 3 greater than n")
        i = 0
        while 3**i < n:
            i = i+1
        m = 3**i

    DPRINT("To generate literals\tn:",n,"\tm:", m)

    #Generate the map and store the rand indices in a dict 
    randomized_input_indices, N_M_map = searchNMmap(n,m) 
    json.dump(N_M_map, open("tmp/N_M_map.txt",'w'))       #Write to a file 
    print(N_M_map)
    json.dump(randomized_input_indices, open("tmp/rand_indices.txt",'w'))       #Write to a file 
    return randomized_input_indices, m, N_M_map

def psiFunction(randomized_input_indices, m):
    # Maps row indices of distribution matrix to nodes - returns a list of node indices  
    if not (len(randomized_input_indices) == m):
        print("Error!: The number of random indices and leaves is not equal!")
    
    #build a tree from the leaves 
    dist_matrix_row_indices = maj3_tree_root_index_list(m)      #Indicates which row of M is assigned which leaf index
    DPRINT("dist_matrix_row_indices = ", dist_matrix_row_indices)
    dist_matrix_row_node_indices = []    
    for i in range(len(dist_matrix_row_indices)):
        dist_matrix_row_node_indices.append(randomized_input_indices[dist_matrix_row_indices[i]])

    json.dump(dist_matrix_row_node_indices, open("tmp/row_node_indices.txt",'w')) 

    return dist_matrix_row_node_indices


def genShareMatrix(M,RHO):
    S = M.dot(RHO) # works well for sparse matrices
    DPRINT("\nSecret is RHO[0]", RHO[0], "\n")
    return S

def randVecZR(vec_len):
    return [group.random(ZR) for x in range(vec_len)]

def bbssShareGen(M):
    d = len(M)
    e = len(M[0])
    if debug:
        print("dM",d , "e:",e)
    
    secret = randVecZR(1)
    rhos   = randVecZR(e-1) 
    RHO = secret + rhos 
    RHO = np.array(RHO)
    DPRINT("no. of cols of M: ", len(M[0]), "\nRHO:", RHO)
    S = genShareMatrix(M, RHO)
    return S

def bbssShareGen4DKG(M):
    #Usually shareGen should not return RHO, but we return here for DKG 
    d = len(M)
    e = len(M[0])
    
    secret = randVecZR(1)
    rhos   = randVecZR(e-1) 
    RHO = secret + rhos 
    RHO = np.array(RHO)
    S = genShareMatrix(M, RHO)
    return S, RHO


def bbssShareGen4PSS(M, share):
    
    DPRINT("'share' inside bbssShareGen4PSS:", share)

    #Usually shareGen should not return RHO, but we return here for DKG 
    d = len(M)
    e = len(M[0])
   
    secret = [share]
    #secret = secret.append(share)

    DPRINT("secret inside bbssShareGen4PSS:", secret)

    rhos   = randVecZR(e-1) 
    RHO = secret + rhos 
    RHO = np.array(RHO)
    S = genShareMatrix(M, RHO)
    return S, RHO



def assignShares2Nodes(S, dist_matrix_row_node_indices, n):
    if (len(S)!=len(dist_matrix_row_node_indices)): 
        print("Error!: Number of shares and row indices do not match!")
        return 
    Node_shares_map = {k:[] for k in range(n)}
    Node_share_index_map = {i:[] for i in range(n)}
    for i in range(len(dist_matrix_row_node_indices)):
        Node_shares_map[dist_matrix_row_node_indices[i]].append(S[i])
        Node_share_index_map[dist_matrix_row_node_indices[i]].append(i)

    json.dump(Node_share_index_map, open("tmp/node_share_index.txt",'w')) 
    return Node_shares_map, Node_share_index_map


if __name__ == "__main__":

    description = """
    This program provides a Black box secret sharing for (n, 2n/3) threshold access structure
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-n", "--nodes", default=4, type=int, help="number of nodes"
    )   
    args = parser.parse_args()

    n = args.nodes  #Number of nodes




    '''
    #TODO: make file name include threshold t  
    filename = "bbssutil/datasets/n"+str(n)

    ssdata = None 
    try:
        f = open(filename)
        ssdata = f.readlines()
        ssdata = json.loads(ssdata[0])
        DPRINT(ssdata)
    except Exception as e: print("",e, "\nSo moving on")

    if ssdata:
        n        = int(ssdata['n'])
        m        = int(ssdata['m'])
        rand_ind = ssdata['rand_ind']
        N_M_map  = ssdata['map']
        lambdas  = ssdata['lambdas']

    else:
        rand_ind, m, N_M_map = generateLiterals(n)
    '''
    rand_ind, m, N_M_map = generateLiterals(n)

    sharing_start = time.process_time()

    M_filename = "./bbssutil/matrices/"+"m"+str(m)+".txt"
    M = np.loadtxt(M_filename, dtype=int)
    
    row_node_indices = psiFunction(rand_ind, m)
    
    S = bbssShareGen(M)
    assigned_shares, node_share_index = assignShares2Nodes(S,row_node_indices, n)

    sharing_end = time.process_time()

    sharing_time = (sharing_end - sharing_start)*1000

    DPRINT("Assigned shares':", assigned_shares)
    DPRINT("Node share index:", node_share_index)

    filename = "tmp/timing_n_"+str(n)+"without_filereading"
    with open (filename,'a') as f:
        f.write(str(sharing_time)+"\n")

    '''
    Node_index= {k:[] for k in range(n)}
    #TODO: Do not search for N_M-map, use from the stored datasets 

    rand_ind, m, N_M_map = generateLiterals(n)
    print("rand_ind:", rand_ind, "\nm:", m , "\nN_M_map", N_M_map)

    M_filename = "./util/matrices/"+"m"+str(m)+".txt"
    M = np.loadtxt(M_filename, dtype=int)
    if debug:
        print("Matrix M loaded from file:\n", M)
        print("Dimensions of loaded Matrix M:", M.shape)

    row_node_indices = psiFunction(rand_ind, m)
    print("row_node_indices:", row_node_indices)

    #S = LISS_share_gen(M)

    S = bbssShareGen(M)
    print ("S",S)


    S_dash, R_dash = bbssShareGen4DKG(M)

    assigned_shares, node_share_index = assignShares2Nodes(S,row_node_indices, n)
    if debug:
        print("Assigned shares:", assigned_shares)
        print("node_share_index:", node_share_index)
    '''

    ''' 
    row_indices = []
    #for i in range(3*n//4):
    for i in range(n):
        row_indices = row_indices + node_share_index[i]
    print("Row indices for reconstruction", row_indices)
    '''
    '''
    mt = np.transpose(M[row_indices])
    e  = np.zeros((len(mt),), dtype=int)
    e[0] = 1

   ''' 
