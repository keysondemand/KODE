import sys , json, re , time, csv   
import os, threading, socket, ast 
import numpy as np  

sys.path += ['./','../','../../']

from charm.core.engine.util     import *
from OpenSSL                    import SSL, crypto
from sys       import argv 
from time      import sleep
from operator  import add 

from conf.connectionconfig       import *
from conf.groupparam             import *
from util.connectionutils        import *
from util.awstransactionbroadcast   import *
from util.nizk                   import *

from util.node_functions         import *

from secretsharing.shamir.shamirsharing import *

debug = 0 
MALICIOUS = 0 
broadcast_counter = 0 

peers                       = {}
connections                 = {}

my_rcvd_shares              = {}
my_rcvd_shares_dash         = {}
my_rcvd_shares_strings      = {}
my_rcvd_shares_dash_strings = {}

peer_share_commits          = {}
peer_dlog_commits           = {}

generated_shares            = {}

complaints                  = {}
records                     = {}
nizks                       = {}

accused_nodes               = []
nodes_verification_failed   = []

QualifiedSet                = []
DisqualifiedSet             = []

M = 0 
N_NODES = 0
MALICIOUS = 0 
node_share_index = 0 
