import json, requests, base64, codecs, time
from charm.toolbox.ecgroup import ECGroup, G
from charm.toolbox.eccurve import prime192v1, prime192v2
from charm.core.engine.util import *

import re

debug = 0


def broadcast(tobdx, key):
    data_handling_start = time.process_time()

    # url = "'http://localhost:46657/"

    payload = json.dumps(tobdx)
    payload = codecs.encode(str.encode(payload), "hex")
    transaction_string = "http://localhost:26657/broadcast_tx_commit?tx=" + '"' + key + "=" + str(payload) + '"'

    data_handling_end = time.process_time()

    data_handling_time = (data_handling_end - data_handling_start) * 1000

    post_request_start = time.process_time()
    r = requests.post(transaction_string)
    post_request_end = time.process_time()

    post_request_time = (post_request_end - post_request_start) * 1000

    if debug:
        if r:
            print("Broadcast Success")
            print(r.text)
    return r


def query(key):
    # url = "'http://localhost:46657/"
    query_string = "http://localhost:26657/abci_query?data=" + '"' + key + '"'
    r = requests.post(query_string)

    rj = json.loads(r.text)
    value = base64.b64decode(rj['result']['response']['value'])
    # base64decoded = base64.b64decode(value)
    stripped = value[2:len(value) - 1]
    hexdecoded = codecs.decode(stripped.strip(), "hex_codec")

    # print(decoded)
    final_string = hexdecoded.decode("utf-8")
    final_json = json.loads(final_string)

    return final_json


if __name__ == "__main__":
    key = "ID1tx_count1epoch0"
    r = query(key)

    commits = r['BroadcastCommit']
    print(commits)
    x = re.findall(r"'(.*?)'", commits, re.DOTALL)
    print(x)
