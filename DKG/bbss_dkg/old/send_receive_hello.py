import sys , json, re , time, csv, requests   
import os, threading, socket, ast
import argparse

from OpenSSL                    import SSL, crypto
from sys                        import argv 
from time                       import sleep
from operator                   import add

sys.path += ['./','../','../../']

#KODE related configs and utils
from conf.connectionconfig                      import *
from conf.groupparam                            import *
from util.connectionutils                       import *

MALICIOUS = 0
AWS = 1

#BASE_PORT = 6566
BASE_PORT = 11000
if AWS:
    MY_IP = ((requests.get('http://checkip.amazonaws.com')).text).strip()
else:
    MY_IP = "127.0.0.1"

broadcast_counter = 0

peers = {}
connections = {}


def serverSock(MY_IP, MY_PORT):
    serversock  = socket.socket ( socket.AF_INET , socket.SOCK_STREAM )
    serversock.bind ( ( '', MY_PORT ) )
    serversock.listen ()
    peer_count = 0
    while True:
        peer_con , peer_addr = serversock.accept () 
        data_received = peer_con.recv(1024)    #TODO: change this from int to data directly 
        print("data_received:", data_received)
        if data_received:
            print("Received something: hello packet")
            
        peer_con.close()

def sendId2peers(nid ):

    print("Sending a packet to node 2")

    node_index = 2
    clientsock  = socket.socket ( socket.AF_INET , socket.SOCK_STREAM )
    clientsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    IP = "54.168.155.248"
    clientsock.connect ( ( IP , BASE_PORT+ node_index ) )
    print ( "Connected - Sending Hello to PORT" , BASE_PORT + node_index , " of Node" , node_index )
    clientsock.sendall(b'Hello World')
    clientsock.close()

def node_thread(nid):
    #id = nid 
    print("Starting Node: ", nid)
    MY_PORT = BASE_PORT + nid
    print("PHASE0: Attempting handshake with all the nodes")

    node_server_thread = threading.Thread(target = serverSock, args = (MY_IP, MY_PORT))
    node_server_thread.start()

    sleep_time = 5*(N_NODES - int(nid))
    sleep(sleep_time)

    node_client_thread = threading.Thread(target = sendId2peers, args = (nid, ))
    node_client_thread.start()
    node_client_thread.join()
    node_server_thread.join()
    
    print("PHASE0: Finished the first handshake with all the nodes")
    

if __name__ == "__main__" :

    description = """ 
    This program provides a single node running the DKG instance 
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-i", "--iden", default=0, type=int, help="node id "
    )   

    parser.add_argument(
        "-n", "--nodes", default=4, type=int, help="number of nodes in DKG"
    )   

    args = parser.parse_args()

    global N_NODES
    N_NODES = args.nodes

    node_thread(int(args.iden))

    sys.exit(0)
    




