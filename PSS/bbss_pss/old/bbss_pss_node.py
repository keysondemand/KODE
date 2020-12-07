import sys , json, re, time, csv    
import os, threading, socket, ast
import numpy as np 

sys.path += ['./','../','../../']

from OpenSSL     import SSL, crypto
from sys         import argv 
from time        import sleep
from operator    import add
from collections import defaultdict

from charm.core.engine.util     import *
from charm.core.math.integer    import *

from conf.connectionconfig                      import *
from conf.groupparam                            import *
from util.connectionutils                       import *
from util.transactionbroadcast                  import *
from util.nizk                                  import *
from secretsharing.blackbox.bbssutil.rhocommit  import *

debug = 0

MALICIOUS = 0

BASE_PORT = 6566
MY_IP = "127.0.0.1"

broadcast_counter = 0

peers = {}
connections = {}

my_rcvd_shares               = defaultdict(dict)
my_rcvd_shares_dash          = defaultdict(dict)
my_rcvd_shares_strings       = defaultdict(dict)
my_rcvd_shares_dash_strings  = defaultdict(dict)

peer_share_commits           = defaultdict(dict)
peer_dlog_commits            = defaultdict(dict)

generated_shares             = defaultdict(dict)

complaints                   = defaultdict(dict)
records                      = defaultdict(lambda: defaultdict(dict))
nizks                        = defaultdict(lambda: defaultdict(dict))
#nizks                        = defaultdict(dict)

node_indices_not_verified           = defaultdict(dict)

accused_nodes                = set()
nodes_verification_failed    = set()
QualifiedSet                 = set()
DisqualifiedSet              = set()

#my_accused_indices           = defaultdict(dict)


tx_count = 0
epoch = 0


def DPRINT ( *args , **kwargs ) :
    if debug:
        print ( *args , **kwargs )

def deserializeElements(objects):
    object_byte_strings = re.findall(r"'(.*?)'", objects , re.DOTALL)
    object_strings  = [ str.encode(a) for a in object_byte_strings]
    elements = [group.deserialize(a) for a in object_strings]
    return elements


def verifyConnection(conn, cert, errnum, depth, ok):
    return ok

def initSSLContext():
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_options(SSL.OP_NO_SSLv2)
    ctx.set_options(SSL.OP_NO_SSLv3)
    ctx.set_verify(
            SSL.VERIFY_PEER, verifyConnection
    ) # Demand a Certificate
    ctx.use_privatekey_file(CLIENT_PVT_KEY_FILE)
    ctx.use_certificate_file(CLIENT_CERT_FILE)
    ctx.load_verify_locations(CA_FILE)
    return ctx 


def serverSock(MY_IP, MY_PORT):
    ctx = initSSLContext()
    s  = SSL.Connection( ctx , socket.socket ( socket.AF_INET , socket.SOCK_STREAM ))
    s.bind ( ( '', MY_PORT ) )
    s.listen ( N_NODES)
    for peer in range ( N_NODES-1 ) : 
        try:
            peer_con , peer_addr = s.accept ( ) 
            pid = recvInt ( peer_con)    #TODO: change this from int to data directly 
            print ( "Received Hello from the node " , pid , " at " , str ( peer_addr ) ) 
            peers[ pid ] = peer_con 
            #TODO: add acknowledgement? 
        except Exception as e: print(e)
    
def sendId2peers(id ):
    ctx = initSSLContext ( )

    for node_index in range ( N_NODES) :
        if  (node_index != id) :
            DPRINT("Attempting to send Hello to Node", node_index)
            try:
                s = SSL.Connection ( ctx , socket.socket ( socket.AF_INET , socket.SOCK_STREAM ))
                s.connect ( ( "127.0.0.1" , BASE_PORT+ node_index ) )
                connections [node_index] = s
                DPRINT ( "Sending Hello to PORT" , BASE_PORT + node_index , " of Node" , node_index )
                sendInt ( s , id )
            except Exception as e: print("Error while sending hello to node_id:", node_index, e)

def sendShareCommits2Peers(M, id):
    global tx_count 
    global epoch 

    ###
    #--- read shares 
    #Read M from file 
    #M = np.loadtxt("./temp/m9.txt", dtype=int)    #TODO: Change this to dynamic file path 
    #M = np.loadtxt("M.txt", dtype=int)
    #M = np.array(M)

    share_filename      = "./tmp/node" + str(id) + "share.txt"
    share_dash_filename = "./tmp/node" + str(id) + "share_dash.txt"

    f     = open(share_filename)
    fdash = open(share_dash_filename)

    keystrings     = f.readlines()
    keydashstrings = fdash.readlines()

    DPRINT("key strings:",       keystrings)
    DPRINT("key dash  strings:", keydashstrings)

    keystrings     = keystrings[0]
    keydashstrings = keydashstrings[0]

    my_shares       = deserializeElements(keystrings)
    my_shares_dash  = deserializeElements(keydashstrings)

    DPRINT("my shares:"     , my_shares)
    DPRINT("my shares dash:", my_shares_dash)
    
    #####
    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))
    #node_share_index = json.load(open("./tmp/node_share_index.txt"))
    my_share_indices = node_share_index[str(id)] 

    print("my_share_indices:", my_share_indices)

    DPRINT("my node share index:", node_share_index[str(id)])
    DPRINT("my_shares length:", len(my_shares))

    N_M_map          = json.load(open("../../secretsharing/blackbox/tmp/N_M_map.txt"))
    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))
    
    DPRINT("node_share_index", node_share_index)
    DPRINT("node_share_index.keys()", node_share_index.keys())


    for sindex in range(len(my_share_indices)):
    #for sindex in range(len(my_shares)):

        tx_count = tx_count + 1
        ctx = initSSLContext ( )

        DPRINT("my_shares[sindex]:", my_shares[sindex])
        DPRINT("my_shares_dash[sindex]:", my_shares_dash[sindex])

        if MALICIOUS:
            S, S_dash , rho_commits, rho_commit_strings, RHO, RHO_dash, dlog_commits, dlog_commit_strings  = rhoCommitPSS(M, my_shares[sindex], my_shares_dash[sindex], MALICIOUS)
        else:
            S, S_dash , rho_commits, rho_commit_strings, RHO, RHO_dash, dlog_commits, dlog_commit_strings  = rhoCommitPSS(M, my_shares[sindex], my_shares_dash[sindex])

        querykey = "ID"+str(id)+"tx_count"+str(tx_count)+"epoch"+str(epoch) + str(time.strftime("%Y-%m-%d-%H-%M-%S"))
        #print(querykey)
    
        RHO_strings = []
        RHO_dash_strings = []
        for i in range(len(RHO)):
            RHO_strings.append(group.serialize(RHO[i]))
            RHO_dash_strings.append(group.serialize(RHO_dash[i]))
   
        rindex = my_share_indices[sindex] 
        print("sindex:", sindex)
        print("rindex:", rindex)
    
        #Save random shares generated by self 
        generated_shares[str(rindex)]['S']                      = str(S)
        generated_shares[str(rindex)]['S_dash']                 = str(S_dash)
        generated_shares[str(rindex)]['PedersenCommits']        = str(rho_commits)
        generated_shares[str(rindex)]['PedersenCommitStrings']  = str(rho_commit_strings)
        generated_shares[str(rindex)]['RHOStrings']             = str(RHO_strings)
        generated_shares[str(rindex)]['RHODashStrings']         = str(RHO_dash_strings)
        generated_shares[str(rindex)]['DlogCommits']            = str(dlog_commits)
        generated_shares[str(rindex)]['DlogCommitStrings']      = str(dlog_commit_strings)
    
        ############# Broadcast using Tendermint #####################
        tobdx= {'my_id':id, 'BroadcastCommit':str(rho_commit_strings), 'epoch': 0} 
        broadcast(tobdx, querykey)
        
        DPRINT("S:",S)
        DPRINT("rho_commits:", rho_commits)
        DPRINT("RHO:", RHO)
        #either send to the stored PID or just send to the node list 
        #here sending to each stored node in the peer list 
    
        DPRINT("printing peer list", peers)
    
        #N_M_map = json.load(open("./tmp/N_M_map.txt"))    
        #node_share_index = json.load(open("./tmp/node_share_index.txt"))    

        
        for pid in list(connections.keys()):
            #records[pid] = defaultdict(dict)
    
            #converting elements to strings before sending 
            DPRINT("pid:", pid)
            DPRINT("node_share_index[pid]", node_share_index[str(pid)])
    
            shares = []
            shares_dash = []
    
            shares_strings  = []
            shares_dash_strings  = []
    
            for index in node_share_index[str(pid)]:
                shares.append(S[index])
                shares_dash.append(S_dash[index])
    
                shares_strings.append(group.serialize(S[index]))
                shares_dash_strings.append(group.serialize(S_dash[index]))
    
            #shares = S[node_share_index[str(pid)]]
            DPRINT(shares)
    
            #data_to_send = {'my_id':id, 'rho_commits': str(rho_commits), 'share':shares }
            data_to_send = {'msg_type':"SHARES", 
                            'my_id':id, 
                            'my_share_id':str(rindex),
                            'sindex':str(sindex), 
                            #'rho_commits': str(rho_commits), 
                            #'share':str(shares), 
                            'share_strings':str(shares_strings), 
                            'share_dash_strings':str(shares_dash_strings), 
                            'key':querykey}
            #data_to_send = {'my_id':id, 'rho_commits': str(rho_commits), 'share':str(S[pid])}
            data_to_send = json.dumps(data_to_send)
    
            #Store what is being sent for later usage during complaints
             
            records[pid][str(sindex)] = data_to_send
            
            try:
            #print (data_to_send)
                send_data(connections[pid], data_to_send)
            except Exception as e: print(e)

def receive_shares():
    #TODO: Add time-out 
    
    #node_share_index = json.load(open("./temp/node_share_index.txt"))
    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))

    count_peer_shares_received = {}
    for pid in peers.keys():
        count_peer_shares = 0
        for rindex in range(len(node_share_index[str(pid)])):

            try:
                
                share_commits_rcvd = recv_data(peers[pid])
                share_rcvd = json.loads(share_commits_rcvd)
            except Exception as e: print("Exception in receiving shares for pid:",pid, " rindex:", rindex, " e:", e)
                
            else:
                DPRINT ("\nReceived something:\n", share_rcvd)

                if share_rcvd:
                    count_peer_shares = count_peer_shares + 1
        
                #my_rcvd_shares[pid]= ast.literal_eval(share_rcvd['share'])[0][0]
                #my_rcvd_shares[pid][str(rindex)]= ast.literal_eval(share_rcvd['share'])
                #print("My received shares", my_rcvd_shares)
                '''
                peer_share_commits[pid]= ast.literal_eval(share_rcvd['rho_commits'])
                '''
                
                #Store in strings from for complaint phase
                my_rcvd_shares_strings[pid][str(rindex)] = share_rcvd['share_strings']
                my_rcvd_shares_dash_strings[pid][str(rindex)]= share_rcvd['share_dash_strings']
        
                #Deserialize to obtain the values
                my_rcvd_shares[pid][str(rindex)]= deserializeElements(share_rcvd['share_strings'])
                my_rcvd_shares_dash[pid][str(rindex)]= deserializeElements(share_rcvd['share_dash_strings'])
                #print("My received shares", my_rcvd_shares)
        
                query_key = share_rcvd['key'] 
                #############Query from Tendermint############
                
                queried_result = query(query_key)
                #print("queried_result", queried_result)
                
                commits = queried_result['BroadcastCommit']
                final_commits = deserializeElements(commits)
                DPRINT("final_commits:", final_commits)
        
                DPRINT("\nExtracted the share", my_rcvd_shares[pid][str(rindex)])
                DPRINT(type(my_rcvd_shares[pid][str(0)]))
                peer_share_commits[pid][str(rindex)] = final_commits 
        
                try:
                    pss_share_filename = "./tmp/node" + str(id) + "pss_share.txt"
                    json.dump(str(my_rcvd_shares[pid][str(rindex)]), open(pss_share_filename,'a'))
                except Exception as e: print("Exception in dumping data:", e)

            #except Exception as e: print("Exception in receiving shares for pid:",pid, " rindex:", rindex, " e:", e)
        count_peer_shares_received[pid] = count_peer_shares
    DPRINT("count_peer_shares_received" , count_peer_shares_received)

    for pid in peers.keys():
        if len(node_share_index[str(pid)]) != count_peer_shares_received[pid]:
            print("Node", pid, "has not shared all its shares")
        else:
            print("Node", pid, "has shared all its shares")


def add_received_shares():
    return

def verify_received_shares(M, id):
    #M = np.loadtxt("m3.txt", dtype=int)             #TODO: Change the filename to variable 
    #node_share_index = json.load(open("./temp/node_share_index.txt"))
    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))
    M_row_index_for_pid = node_share_index[str(id)]  
    M_my_rows = M[node_share_index[str(id)]]
    DPRINT("My M rows:", M_my_rows)
    
    for pid in peers.keys():
         node_indices_not_verified[pid] = []
         print("pid:", pid)
         for rindex in range(len(node_share_index[str(pid)])):
 
             peer_rho_commits =  peer_share_commits[pid][str(rindex)]
             shares_rcvd      =  my_rcvd_shares[pid][str(rindex)]
             shares_dash_rcvd =  my_rcvd_shares_dash[pid][str(rindex)]
     
             if len(M_my_rows) != len(shares_rcvd):
                 print("Eroor!: The number of nodes' rows in M and number of shares received are not same")
     
             '''
             com(s_i) = (C_i)**(m_{i,1}) * (C_i)**(m_{i,2}) ... * (C_i)**(m_{i,e})
             '''
     
             DPRINT("shares_rcvd", shares_rcvd)
             DPRINT("shares_dash_rcvd", shares_dash_rcvd)
     
             verified_shares_counter = 0
     
             #Check each received share
             for i in range(len(shares_rcvd)):
                 DPRINT("M_my_rows[",i,"]:", M_my_rows[i])
                 DPRINT("peer_rho_commits", peer_rho_commits)
                 computed_share_commitment = (g ** shares_rcvd[i]) * ( h ** shares_dash_rcvd[i])
     
                 commitment_product = unity 
                 DPRINT("Initial commitment product", commitment_product)
                 
                 for j in range(len(M_my_rows[i])) :
                     if M_my_rows[i][j] == 1:
                        #b = group.init(ZR, int(M_my_rows[i][j]))
                        commitment_product = commitment_product * peer_rho_commits[j] 
                 
                     DPRINT("computed_share_commitment:", computed_share_commitment, "commitment_product", commitment_product)
                 if (computed_share_commitment == commitment_product):
                     DPRINT("Share[",i,"] Verified")
                     verified_shares_counter += 1
                 
             if(verified_shares_counter == len(shares_rcvd)):
                 print("Great, share verified for peer ID:",pid, "and rindex", rindex )
     
     
                 #Adding this just to check functionality 
                 #*****************************************
                 #TODO: Remove this 
                 #nodes_verification_failed.append(pid)         
                 #node_indices_not_verified[pid].append(rindex) 
             else:
                 print("Something looks fishy, raising a complaint against peer ID:", pid)
                 #nodes_verification_failed.append(pid)         
                 nodes_verification_failed.add(pid)         
                 node_indices_not_verified[pid].append(rindex) 

        
def broadcastFailedNodeList(nid):

    print("Broadcasting accusations now")

    global tx_count
    global epoch
    tx_count = tx_count + 1
    accusation_query_key = ""

    total_accusations = []
    for pid in nodes_verification_failed:
        accusation = defaultdict(dict)
        accusation['node_id']= pid
        accusation['index']  = node_indices_not_verified[pid]
        #for each index that did not get verified from peer pid 
        for rindex in node_indices_not_verified[pid]:
            accusation[pid][rindex]  = rindex 
            accusation['shares'][str(rindex)] = my_rcvd_shares_strings[pid][str(rindex)]
            accusation['shares_dash'][str(rindex)] = my_rcvd_shares_dash_strings[pid][str(rindex)]

        total_accusations.append(accusation)
    accusations_string = json.dumps(total_accusations)

    complaint = {'msg_type':"COMPLAINT",
                 'my_id':nid,
                 'accusation': accusations_string
                 #'accusation': total_accusations
                 }
    complaint = dict(complaint)
    accusation_querykey = "AccusationFromID"+str(nid)+"tx_count"+str(tx_count)+"epoch"+str(epoch) + str(time.strftime("%Y-%m-%d-%H-%M"))


    ######### Broadcast the complaint using Tendermint 
    broadcast(complaint, accusation_querykey)


    ########## Send indication to all nodes 
    for pid in list(connections.keys()):
        if debug:
            print("pid:", pid)

        yesorno = ""
        if pid in nodes_verification_failed:
            yesorno = "yes"
        else:
            yesorno = "no"

        data_to_send = {'msg_type'    :"COMPLAINT_INDICATION",
                        'my_id'       :nid,
                        'key'         :accusation_querykey,
                        'accusing_you': yesorno }
        #data_to_send = {'my_id':id, 'rho_commits': str(rho_commits), 'share':str(S[pid])}
        data_to_send = json.dumps(data_to_send)
        DPRINT(data_to_send)
        send_data(connections[pid], data_to_send)



def handleBrocastComplaints(M,nid):
     
    for pid in peers.keys():
        try :
            broadcastedComplaint = recv_data(peers[pid])
        except:
            print("Exception")
            continue

        else:    
            broadcastedComplaint = json.loads(broadcastedComplaint)

            if (broadcastedComplaint['msg_type'] == "COMPLAINT_INDICATION"):
                am_I_accused = broadcastedComplaint['accusing_you']
                '''
                if (am_I_accused == "yes"):
                    accused_by_id = broadcastedComplaint['my_id'] 
                    #Now broadcast shares sent to the node of accused_by_id 

                    global tx_count
                    global epoch
                    tx_count = tx_count + 1

                    broadcast_sent_shares = records[accused_by_id]['SENT_SHARES']
                    #TODO: Check this again
                    #broadcast_sent_shares = json.dumps(broadcast_sent_shares)

                    tobdx= {'my_id':nid, 'Reply2Complaint_SentShares':broadcast_sent_shares, 'epoch': 0, 'accused_by_id':accused_by_id}
                    replykey = "From"+str(nid)+"Reply2AccusationBy"+str(accused_by_id)+"tx_count"+str(tx_count)+"epoch"+str(epoch)+ str(time.strftime("%Y-%m-%d-%H-%M"))

                    ############ Tendermint Broadcast#########
                    broadcast(tobdx, replykey)

                    # Again send this to everyone 
                    for pid in list(connections.keys()):
                        if debug:
                            print("pid:", pid)

                    data_to_send = {'msg_type'       :"REPLY2COMPLAINT",
                                    'my_id'          :nid,
                                    'key'            :replykey,
                                    'accused_by_id'  :accused_by_id
                                    }
                    #data_to_send = {'my_id':id, 'rho_commits': str(rho_commits), 'share':str(S[pid])}
                    data_to_send = json.dumps(data_to_send)
                    DPRINT(data_to_send)
                    try:
                        send_data(connections[pid], data_to_send)
                    except Exception as e: print("Exception in sending data to pid:", pid, e)
                '''
                # Check validity of the accusation                 

                accusation_querykey = broadcastedComplaint['key']
                print("Accusation query key:", accusation_querykey)
                ###### query from Tendermint  
                complaints[pid] = query(accusation_querykey)

                DPRINT(complaints[pid])

                complaintVerify(complaints[pid], M, nid)

                #TODO: This part can be modular - can reuse code from verifying shares 


def complaintVerify(complaints, M, nid):


    print("Entering Complaint verify function")

    accuser_nid = complaints['my_id'] #Node that raised a complaint, we need to use his rows 
    accusations = complaints['accusation']
    accusations = json.loads(accusations) #List of dictionaries - Many nodes against whom accuser sends a complaint 

    #node_share_index = json.load(open("./temp/node_share_index.txt"))
    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))
    M_rows = M[node_share_index[str(accuser_nid)]]

    print("Accuser_node:", accuser_nid)

    accusation_no = 0
    for accstn in accusations:
        accusation_no += 1
        DPRINT("accstn:",accstn)
        accused_nid = accstn['node_id']

        accused_rindices = accstn['index']

        #Maintain a dictionary which keeps the rindices of each node that are accused 
        if isinstance(accused_rindices, list):
            accused_indices[accused_nid].update(accused_rindices)
            if (accused_nid == nid):
                my_accused_indices[accuser_nid].update(accused_rindices)
                print("my_accused_indices[",accuser_nid, "]:", my_accused_indices[accuser_nid])
        else:
            accused_indices[accused_nid].add(accused_rindices)
            if (accused_nid == nid):
                my_accused_indices[accuser_nid].add(accused_rindices)
                print("my_accused_indices[",accuser_nid, "]:", my_accused_indices[accuser_nid])

        #Set of all accused nodes 
        accused_nodes.add(accused_nid)

        #What all nodes complained against a node
        complaining_nodes[accused_nid].add(accuser_nid)

        if len(complaining_nodes[accused_nid]) > (N_NODES // 3):
            global QualifiedSet, DisqualifiedSet
            DisqualifiedSet.add(accused_nid)

        #********************
    #return 
        #********************

    '''        
        if (accused_nid == nid):
            continue 
        verified_shares_number = 0
        for rindex in accused_rindices:
            accuser_shares = deserializeElements(accstn['shares'][str(rindex)])
            accuser_shares_dash  = deserializeElements(accstn['shares_dash'][str(rindex)])
    
            peer_rho_commits =  peer_share_commits[accused_nid][str(rindex)]    
    
            verified_shares_counter = 0
    
            #Check each received share
            for i in range(len(accuser_shares)):
                if debug:
                    print("M_rows[",i,"]:", M_rows[i])
                computed_share_commitment = (g ** accuser_shares[i]) * ( h ** accuser_shares_dash[i])
    
                commitment_product = unity 
    
                for j in range(len(M_rows[i])) :
                    if M_rows[i][j] == 1:
                        b = group.init(ZR, int(M_rows[i][j]))
                        commitment_product = commitment_product * (peer_rho_commits[j] ** b)
    
                if debug:
                    print("computed_share_commitment:", computed_share_commitment, "commitment_product", commitment_product) 
                if (computed_share_commitment == commitment_product):
                    print("Share[",i,"] Verified for rindex ", rindex, "accusation no ", accusation_no)
                    verified_shares_counter += 1
    
            if(verified_shares_counter == len(accuser_shares)):
                print("Great, all shares verified for peer ID:",accused_nid, " rindex:", rindex )
                verified_shares_number = verified_shares_number + 1
        if verified_shares_number == len(accused_rindices):
            print("Its a wrong accusation!!")
            #global QualifiedSet, DisqualifiedSet
            QualifiedSet.add(accused_nid)
            DisqualifiedSet.add(accuser_nid)
            return 
        else:
            DisqualifiedSet.add(accused_nid)
    '''


def reply2BroadcastComplaints(M,nid): 
    print("my_accused_indices:", my_accused_indices)

    #my_accused_indices = accused_indices[nid]

    for pid in peers.keys():
        accused_by_id = pid
        if my_accused_indices[pid]:

            for rindex in my_accused_indices[pid]: 
                print("rindex", rindex)
                print("accused_by_id", accused_by_id)
                #print("records:", records[accused_by_id])
                broadcast_sent_shares = records[accused_by_id][str(rindex)]
                #TODO: Check this again
                broadcast_sent_shares = json.dumps(broadcast_sent_shares)
                
                tobdx= {'my_id':nid, 'Reply2Complaint_SentShares':broadcast_sent_shares, 'epoch': 0, 'accused_by_id':accused_by_id}
                replykey = "From"+str(nid)+"Reply2AccusationBy"+str(accused_by_id)+"tx_count"+str(tx_count)+"epoch"+str(epoch)+ str(time.strftime("%Y-%m-%d-%H-%M-%S"))
                
                ############ Tendermint Broadcast#########
                broadcast(tobdx, replykey)
                data_to_send = {'msg_type'       :"REPLY2COMPLAINT",
                                'my_id'          :nid,
                                'key'            :replykey,
                                'accused_by_id'  :accused_by_id, 
                                'rindex'         :rindex
                                }
                #data_to_send = {'my_id':id, 'rho_commits': str(rho_commits), 'share':str(S[pid])}
                data_to_send = json.dumps(data_to_send)
                DPRINT(data_to_send)

                # Again send this to everyone 
                for pid in list(connections.keys()):
                    try:
                        send_data(connections[pid], data_to_send)
                    except Exception as e: print("Exception in sending data to pid:", pid, e)



def handleBrocastReplies(M,nid):
    print("Handling Broadcast Replies")
    print("Accused_nodes:", accused_nodes)


    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))

    for pid in peers.keys():
        if pid in accused_nodes:
            print("pid:", pid)
            print("complaining nodes:", complaining_nodes[pid])
            
            #Inlclude myself in the complaining nodes if I am not malicious
            if not MALICIOUS:
                complaining_nodes[pid].add(nid)
            for accuser in complaining_nodes[pid]:
                print("accused_indices[pid]:", accused_indices[pid])
                for rindex in accused_indices[pid]:
                    try :
                        broadcastedReply = recv_data(peers[pid])
                        DPRINT("broadcastedReply:", broadcastedReply)
                    except Exception as e: 
                        print("Exception in handling broadcast replies to complaints at peer id:", pid, "e:", e)
                        continue

                    else:
                        broadcastedReply = json.loads(broadcastedReply)

                        if (broadcastedReply['msg_type'] == "REPLY2COMPLAINT"):
                            querykey = broadcastedReply['key']
                            reply2complaint = query(querykey)
                            accuser_nid = reply2complaint['accused_by_id']
                            accused_nid  = reply2complaint['my_id']

                            accuser_shares_sent = json.loads(reply2complaint['Reply2Complaint_SentShares'])

                            #print("accuser_shares_sent", accuser_shares_sent)
                            #print("type:", type(accuser_shares_sent))
                            accuser_shares_sent = json.loads(accuser_shares_sent)
                            share_strings = accuser_shares_sent['share_strings']
                            print("share_strings:", share_strings)


                            #print("accuser_shares_sent:", accuser_shares_sent)
                            M_rows = M[node_share_index[str(accuser_nid)]]

                            verified_shares_number = 0
                            accuser_shares = deserializeElements(accuser_shares_sent['share_strings'])
                            accuser_shares_dash  = deserializeElements(accuser_shares_sent['share_dash_strings'])
                            index = accuser_shares_sent['sindex']
    
                            peer_rho_commits =  peer_share_commits[accused_nid][index]    
    
                            verified_shares_counter = 0
    
                            for i in range(len(accuser_shares)):
                                #print("M_rows[",i,"]:", M_rows[i])
                                computed_share_commitment = (g ** accuser_shares[i]) * ( h ** accuser_shares_dash[i])
                                commitment_product = unity 
                                for j in range(len(M_rows[i])) :
                                    if M_rows[i][j] == 1:
                                        b = group.init(ZR, int(M_rows[i][j]))
                                        commitment_product = commitment_product * (peer_rho_commits[j] ** b)
    
                                DPRINT("computed_share_commitment:", computed_share_commitment, "commitment_product", commitment_product) 
                                if (computed_share_commitment == commitment_product):
                                    print("Share[",i,"] Verified for rindex ", rindex, "accusation no ", accusation_no)
                                    verified_shares_counter += 1
    
                            if(verified_shares_counter == len(accuser_shares)):
                                print("Great, share verified for peer ID:",accused_nid, " rindex:", rindex )
                                verified_shares_number = verified_shares_number + 1
                            else:
                                print("Shares not verified")
                                global DisqualifiedSet
                                DisqualifiedSet.add(accused_nid)




def broadcastDLogNIZK(nid):


    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))
    my_share_indices = node_share_index[str(nid)] 

    for sindex in range(len(node_share_index[str(nid)])):
        rindex = my_share_indices[sindex]

        dlog_commit_strings     = generated_shares[str(rindex)]['DlogCommitStrings']
        pedersen_commit_strings = generated_shares[str(rindex)]['PedersenCommitStrings']
        RHO_strings             = generated_shares[str(rindex)]['RHOStrings']
        RHO_dash_strings        = generated_shares[str(rindex)]['RHODashStrings']
    
        dlog_commits     = deserializeElements(dlog_commit_strings)
        pedersen_commits = deserializeElements(pedersen_commit_strings)
        RHO              = deserializeElements(RHO_strings)
        RHO_dash         = deserializeElements(RHO_dash_strings)
    
        zkp_vec = nizkpok_vec(dlog_commits, pedersen_commits, RHO, RHO_dash)
    
        tobdx   = {
                'msg_type'    : 'DLOGNIZK',
                'my_id'       : nid,
                'DLogStrings' : str(dlog_commit_strings),
                'PederStrings': str(pedersen_commit_strings),
                'NIZK'        : str(zkp_vec),
                'sindex'      : sindex,  
                'rindex'      : rindex 
                }
    
        global tx_count
        global epoch
        tx_count = tx_count + 1
        querykey = "NIZKID" + str(nid) + "tx_count" + str(tx_count) + "epoch" + str(epoch)+ str(time.strftime("%Y-%m-%d-%H-%M-%S"))
        
        #Tendermint broadcast 
        broadcast(tobdx, querykey)
    
        data_to_send = {
                'msg_type': 'DLogNizkKey',
                'my_id'   : nid,
                'key'     : querykey
                }
        data_to_send = json.dumps(data_to_send)
    
        #Individual key send 
        for pid in list(connections.keys()):
            try:
                send_data(connections[pid], data_to_send)
            except Exception as e: print(e)

def handleDlogNizk(nid):
    node_share_index = json.load(open("../../secretsharing/blackbox/tmp/node_share_index.txt"))
    my_share_indices = node_share_index[str(nid)] 

    for pid in peers.keys():
        share_indices = node_share_index[str(pid)]

        for rindex in range(len(node_share_index[str(pid)])):
            try :
                broadcastedDlogNizk= recv_data(peers[pid])
            except:
                print("Exception: Have not received NIZK from node:", pid)
                continue

            else:
                broadcastedDlogNizk= json.loads(broadcastedDlogNizk)

                if (broadcastedDlogNizk['msg_type'] == "DLogNizkKey"):
                    nizk_nid      = broadcastedDlogNizk['my_id']
                    nizk_querykey = broadcastedDlogNizk['key'] 


                    ###### query from Tendermint  
                    nizks[pid][str(rindex)] = query(nizk_querykey)

                    verifyDlogNizk(nizks[pid][str(rindex)], pid, rindex)
    return 

def verifyDlogNizk(nizks, pid, rindex):
    if (nizks['msg_type'] == "DLOGNIZK" ):
        print("The received message is dlognizk")
    #print("nizks received:", nizks)
    nizk_nid     = nizks['my_id']
    dlog_strings = nizks['DLogStrings']
    pedersen_strings= nizks['PederStrings']
    nizk_vec     = nizks['NIZK']

    #There seems to be some abuse in notation 
    recv_rindex  = nizks['sindex']

    #print("nizk_vec",nizk_vec,"type(nizk_vec):", type(nizk_vec), "nizk_vec[0]", nizk_vec[0])

    nizk_vec =         deserializeElements(nizk_vec)
    dlog_commits =     deserializeElements(dlog_strings)
    pedersen_commits = peer_share_commits[pid][str(recv_rindex)]
    recv_peder_commits = deserializeElements(pedersen_strings)


    #TODO: this is wrong, remove this line
    pedersen_commits = recv_peder_commits


    #Add the first dlog commitment as public key share needed 
    peer_dlog_commits[pid] = dlog_commits[0] 

    #print("pedersen commits:", pedersen_commits)
    #print("recv pedersen commits:", recv_peder_commits)


    '''
    print("Len of pedersen commits:", len(pedersen_commits))
    print("Len of dlog     commits:", len(dlog_commits))
    print("Len of nizk_vec:", len(nizk_vec))
    '''

    proofs = []
    for i in range(len(nizk_vec)//3):
        c = nizk_vec[3*i]
        u1 = nizk_vec[(3*i)+1]
        u2 = nizk_vec[(3*i)+2]
        #print("\n\nsent proof:", [c, u1, u2])
        proofs.append([c,u1,u2]) #Putting them back as lists, not sure if it is needed

        V1_dash = (g ** u1) * (dlog_commits[i] ** c)
        dlog_commit_inv = dlog_commits[i] ** (-1)

        V2_dash = (h ** u2) * ((pedersen_commits[i] * dlog_commit_inv )**c)

        c_dash = group.hash((g,h,dlog_commits[i],pedersen_commits[i], V1_dash, V2_dash), ZR)

        #print("c:",c)
        #print("c_dash:",c_dash)
        #print("c_dash:",c_dash, "dlog_commit:", dlog_commits[i], "pedersen_commit:", pedersen_commits[i], "V1_dash:", V1_dash, "V2_dash", V2_dash)


        c_str = str(c)
        c_str = c_str[:len(c_str)-30]
        c_dash_str = str(c_dash)
        c_dash_str = c_dash_str[:len(c_dash_str)-30]

        global DisqualifiedSet

        #TODO: This is a temporary fix , change charm code 
        if group == group571:
            if c_str == c_dash_str:
                print("The NIZK proof is verified")
            else:
                DisqualifiedSet.add(pid)
        else:
            if (c == c_dash):
                DPRINT("The NIZK proof is verified")
                print("The NIZK proof is verified")
            else:
                DisqualifiedSet.add(pid)

        '''
        if (c == c_dash):
            print("The NIZK proof is verified")
        else:
            global DisqualifiedSet
            DisqualifiedSet.add(pid)
        '''


def dprf_mode(nid, DPRF_PORT):
    ctx = initSSLContext()
    s  = SSL.Connection(ctx,socket.socket(socket.AF_INET,socket.SOCK_STREAM))
    s.bind (( '',DPRF_PORT))
    s.listen (N_NODES + 1) #TODO: Make it just one 

    client_con , client_addr = s.accept ( )
    request = recv_data(client_con)    
    print ( "Received request from the client at " , str ( client_addr ) )
    
    request = json.loads(request)
    print(request)
    X = request['publicstring'] 
    keytype = request['keytype']

    #par_key will be a list 
    par_key = partial_eval(nid, X, keytype )
    serial_par_key = [group.serialize(key) for key in par_key]
    print("serial_par_key:", serial_par_key)
    
    data_to_send= {
            'my_id':nid,
            'partialEval': str(serial_par_key)
            }

    data_to_send = json.dumps(data_to_send)
    #data_to_send = "Server"+ str(nid) + "Says: hi"
    #oclient_con.sendall("Server Says:hi"+str(nid))
    send_data(client_con, data_to_send)

def computePubKey(nid):
    publicKey = group.random(G)
    publicKey = publicKey/publicKey # just make it unity 

    for pid in peers.keys():
        if pid not in DisqualifiedSet:
            publicKey = publicKey * peer_dlog_commits[pid]

    return publicKey 


def node_thread(id):
    DPRINT("Starting Node: ", id)
    MY_PORT = BASE_PORT + id
    DPRF_PORT = MY_PORT + 1000
    #start server part of node to receive Hello


    node_server_thread = threading.Thread(target = serverSock, args = (MY_IP, MY_PORT))
    node_server_thread.daemon = False 
    node_server_thread.start()

    sleep_time = (N_NODES - int(args.id))
    sleep(sleep_time)

    #start client part to send hello to all other peers 
    node_client_thread = threading.Thread(target = sendId2peers, args = (id, ))
    node_client_thread.daemon = False

    node_client_thread.start()

    node_server_thread.join()
    node_client_thread.join()
    
    DPRINT("Finished the first handshake with all the nodes")

    
    #sleep(1) 

    #Read M from file 
    #M = np.loadtxt("./temp/m9.txt", dtype=int)    #TODO: Change this to dynamic file path 

    if N_NODES < 4:
        M = np.loadtxt("../../secretsharing/blackbox/bbssutil/matrices/m3.txt", dtype=int)
    elif N_NODES < 10: 
        M = np.loadtxt("../../secretsharing/blackbox/bbssutil/matrices/m9.txt", dtype=int)
    elif N_NODES < 28: 
        M = np.loadtxt("../../secretsharing/blackbox/bbssutil/matrices/m27.txt", dtype=int)


    share_filename = "./tmp/node" + str(id) + "share.txt"
    f = open(share_filename)
    keystrings = f.readlines()
    keystrings = keystrings[0]
    my_shares = deserializeElements(keystrings)

    
    sharing_start = time.process_time()
    
    share_send_thread = threading.Thread(target=sendShareCommits2Peers, args=(M,id ))
    share_send_thread.daemon = False

    share_send_thread.start()
    share_send_thread.join()

    sharing_end = time.process_time()

    #Receive shares
    #sleep(1)
    receive_start = time.process_time()

    share_receive_thread= threading.Thread(target=receive_shares, args=( ))
    share_receive_thread.daemon = False

    share_receive_thread.start()

    share_send_thread.join()
    share_receive_thread.join()

    receive_end = time.process_time()

    #Verify commitments 
    sleep(1)
    verify_start = time.process_time()

    share_verify_thread = threading.Thread(target=verify_received_shares, args=(M,id ))
    share_verify_thread.daemon = False

    share_verify_thread.start()
    share_verify_thread.join()

    verify_end = time.process_time()
    
    sleep(1)
    #Broadcast complaints
    complaint_start = time.process_time()

    broadcastComplaint_thread= threading.Thread(target=broadcastFailedNodeList, args=(id,))
    broadcastComplaint_thread.daemon = False

    broadcastComplaint_thread.start()
    broadcastComplaint_thread.join()
    complaint_end = time.process_time()

    #Handle all complaints (including on self)
    
    handle_complaint_start = time.process_time()
        
    handleComplaint_thread = threading.Thread(target=handleBrocastComplaints, args=(M, id ))
    handleComplaint_thread.daemon = False

    handleComplaint_thread.start()
    handleComplaint_thread.join()

    handle_complaint_end = time.process_time()

    #Just compare the commitment of each share element of each node from previous epoch - read from a file 
    # Compute own share from qualified set
    '''
    if id != 0:
        my_secret_share = [0]*len(my_rcvd_shares[0])
    else:
        my_secret_share = [0]*len(my_rcvd_shares[1])   #Assuming atleast one other node exists 

    my_pss_secret_shares = []
    pss_share_filename = "./temp/node" + str(id) + "pss_share.txt"

    for key in my_rcvd_shares.keys():
        if key not in DisqualifiedSet:
           my_pss_secret_shares.append( my_rcvd_shares[key] )
           json.dump(my_share_strings, open(pss_share_filename,'a'))
           #my_secret_share = list(map(add, my_secret_share, my_rcvd_shares[key])) 

    #print("my_secret_share", my_secret_share)
    #my_share_strings = [str(group.serialize(share)) for share in my_secret_share] 
    
    #Write secret share to a file 
    #share_filename = "./temp/node" + str(id) + "pss_share.txt"
    #json.dump(my_share_strings, open(share_filename,'a'))
    '''

    complaintReply_start = time.process_time()

    complaintReply_thread = threading.Thread(target=reply2BroadcastComplaints , args=(M, id ))
    complaintReply_thread.daemon = False


    complaintReply_thread.start()
    complaintReply_thread.join()
    
    complaintReply_end = time.process_time()
    print("\nPHASE4: Verifying replies received  against complaints")

    handle_reply_start = time.process_time()

    handleReply_thread = threading.Thread(target=handleBrocastReplies, args=(M, id ))
    handleReply_thread.daemon = False


    handleReply_thread.start()
    handleReply_thread.join()
    
    handle_reply_end = time.process_time()

    sleep(1)


    send_nizk_start = time.process_time()
    #Broadcast NIZK 
    broadcastNizk_thread = threading.Thread(target=broadcastDLogNIZK, args=(id,))
    broadcastNizk_thread.daemon = False

    broadcastNizk_thread.start()
    broadcastNizk_thread.join()
    send_nizk_end = time.process_time()


    #Handle nizk

    handle_nizk_start = time.process_time()
    handleNizk_thread= threading.Thread(target=handleDlogNizk, args=(id,))
    handleNizk_thread.daemon = False

    handleNizk_thread.start()
    handleNizk_thread.join()

    handle_nizk_end = time.process_time()
    '''

    #Run DPRF   
    share_verify_thread = threading.Thread(target=dprf_mode, args=(id,DPRF_PORT ))
    share_verify_thread.daemon = False

    share_verify_thread.start()
    share_verify_thread.join()
    '''

    sharing_time          = sharing_end          - sharing_start
    receive_time          = receive_end          - receive_start
    verify_commit_time    = verify_end           - verify_start
    complaint_time        = complaint_end        - complaint_start
    complaint_handle_time = handle_complaint_end - handle_complaint_start

    send_nizk_time        = send_nizk_end        - send_nizk_start
    handle_nizk_time      = handle_nizk_end      - handle_nizk_start

    print( "sharing_time:",          sharing_time*1000)
    print( "receive_time:",          receive_time*1000)
    print( "verify_commit_time:",    verify_commit_time*1000)
    print( "complaint_time:",        complaint_time*1000)
    print( "complaint_handle_time:", complaint_handle_time*1000)
    print( "send_nizk_time:",        send_nizk_time *1000)
    print( "handle_nizk_time:",      handle_nizk_time *1000)


if __name__ == "__main__" :
    
    description = """
    This program provides a single node running the DKG instance
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-i", "--id", default=0, type=int, help="node id "
    )

    parser.add_argument(
        "-n", "--nodes", default=4, type=int, help="number of nodes in DKG"
    )


    parser.add_argument(
        "-m", "--malicious", default=0, type=int, help="is the node malicious"
    )

    args = parser.parse_args()

    global N_NODES
    global complaint_count
    global complaining_nodes
    global accused_rindices 
    global my_accused_indices

    N_NODES = args.nodes
    accused_rindices   = defaultdict(dict)
    complaint_count    = {k: 0  for k in range(N_NODES)}
    complaining_nodes  = {k: set()  for k in range(N_NODES)}
    accused_indices    = {k: set()  for k in range(N_NODES)}
    my_accused_indices = {k: set()  for k in range(N_NODES)}

    MALICIOUS = args.malicious

    if MALICIOUS:
        print("\nI am a MALICIOUS node\n\n")


    node_thread(int(args.id))

    sys.exit(0)
    




