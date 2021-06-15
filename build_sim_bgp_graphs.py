import socket
import json
import os
import csv
import sys
import subprocess
import pdb
from subprocess import Popen
import time
import settings
import mkit.inference.ixp as ixp
from networkx.readwrite import json_graph
import networkx as nx
import mkit.inference.ip_to_asn as ip2asn
from consts import *


def make_bgp_gr(arr_list, asn_src):
    as_graph = nx.DiGraph()
    for arr in arr_list:
        arr = arr.split(':\n')[-1]
        hops = arr.split('\n')
        hops = [x for x in hops if x]
        if not hops: continue
        if asn_src not in hops:
            print "Source not in path!", hops, asn_src
            continue
        path_hops = hops[:hops.index(asn_src) + 1]
        new_hops = []
        for hop in path_hops:
            if hop in ixp.IXPs:
                continue
            new_hops.append(hop)
        if len(new_hops) <= 1:
            continue
        for i in range(0,len(new_hops)-1):
            as_graph.add_edge(new_hops[i],new_hops[i+1])
    data = json_graph.node_link_data(as_graph)
    s = json.dumps( data )
    with open(GRAPH_SIM_BGP + '%s' % asn_src, "w") as f:
        f.write(s)
    return as_graph
        
TCP_IP = '127.0.0.1'
TCP_PORT = 11002
bgp_graphs = {}
asn_srcs = []
count_ips = 0
with open("per_prefix_count.csv") as fi:
    reader = csv.reader(fi)
    for row in reader:
        if row[0] == 'pref': continue
        if int(row[1]) < 73: break
        ip = row[0]
        asn = ip2asn.ip2asn_bgp(ip)
        asn_srcs.append(asn)

asns = set()
with open("20170201.as-rel.txt") as f:
    for line in f:
        if line.startswith('#'): continue
        src, dst, typ = line.split('|')
        asns.add(src)
        asns.add(dst)
asns = list(asns)
asn_dsts = asns

asn_srcs = list(set(asn_srcs))
print "Getting graphs of ASes with most content"
for asn_src in asn_srcs:
    if not asn_src: continue
    if str(asn_src) in bgp_graphs: continue
    FNULL = open(os.devnull, 'w')
    proc = Popen(['mono',
                  BGPSIM_EXE_LOCATION,
                  '-server11002 ', AS_REL_CYCLOPS_FORMAT,
                  PRECOMP,
                  EXIT_ASNS_BGPSIM],
                 stderr=subprocess.STDOUT)
    time.sleep(10)
    print "Getting all paths from", asn_src
    MESSAGE = asn_src + " -q"
    count = 0 
    for asn_dst in asn_dsts:
        MESSAGE += " " + asn_dst + " " + asn_src
        count += 1
    MESSAGE += " <EOFc> "
    print "Sending message to BGPSim to get %d paths from %s.." % (count, asn_src)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(MESSAGE)
    data = ""
    result = dict()
    buffer_size = 10000000
    while True:
        d = s.recv(buffer_size)
        data += d
        if len(d) == 0:
            break
        if "<EOFs>" in d:
            break

    s.close()
    proc.terminate()
    arr = data.split("-\n")
    gr = make_bgp_gr(arr, asn_src)
    bgp_graphs[asn_src] = gr

with open("top_cust_cone_ips.json") as fi:
    top_cust_cones = json.load(fi)

print "Getting graphs of largest customer cone'd ASes"
asn_srcs = top_cust_cones.keys()
asn_srcs = list(set(asn_srcs))
for asn_src in asn_srcs:
    if not asn_src: continue
    if str(asn_src) in bgp_graphs: continue
    FNULL = open(os.devnull, 'w')
    proc = Popen(['mono',
                  BGPSIM_EXE_LOCATION
                  '-server11002 ', AS_REL_CYCLOPS_FORMAT
                  PRECOMP,
                  EXIT_ASNS_BGPSIM],
                 stderr=subprocess.STDOUT)
    time.sleep(10)
    print "Getting all paths from", asn_src
    MESSAGE = asn_src + " -q"
    count = 0 
    for asn_dst in asn_dsts:
        MESSAGE += " " + asn_dst + " " + asn_src
        count += 1
    MESSAGE += " <EOFc> "
    print "Sending message to BGPSim to get %d paths from %s.." % (count, asn_src)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(MESSAGE)
    data = ""
    result = dict()
    buffer_size = 10000000
    while True:
        d = s.recv(buffer_size)
        data += d
        if len(d) == 0:
            break
        if "<EOFs>" in d:
            break

    s.close()
    proc.terminate()
    arr = data.split("-\n")
    gr = make_bgp_gr(arr, asn_src)
    bgp_graphs[asn_src] = gr

with open("top_eyeball_prefs.json") as fi:
    top_eyeballs = json.load(fi)

print "Getting graphs of largest eyeball ASes"
asn_srcs = top_eyeballs.keys()
asn_srcs = list(set(asn_srcs))
for asn_src in asn_srcs:
    if not asn_src: continue
    if str(asn_src) in bgp_graphs: continue
    FNULL = open(os.devnull, 'w')
    proc = Popen(['mono',
                  BGPSIM_EXE_LOCATION
                  '-server11002 ', AS_REL_CYCLOPS_FORMAT,
                  PRECOMP, EXIT_ASNS_BGPSIM],
                 stderr=subprocess.STDOUT)
    time.sleep(10)
    print "Getting all paths from", asn_src
    MESSAGE = asn_src + " -q"
    count = 0 
    for asn_dst in asn_dsts:
        MESSAGE += " " + asn_dst + " " + asn_src
        count += 1
    MESSAGE += " <EOFc> "
    print "Sending message to BGPSim to get %d paths from %s.." % (count, asn_src)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(MESSAGE)
    data = ""
    result = dict()
    buffer_size = 10000000
    while True:
        d = s.recv(buffer_size)
        data += d
        if len(d) == 0:
            break
        if "<EOFs>" in d:
            break

    s.close()
    proc.terminate()
    arr = data.split("-\n")
    gr = make_bgp_gr(arr, asn_src)
    bgp_graphs[asn_src] = gr

with open("random_ips.json") as fi:
    random_ases = json.load(fi)

print "Getting graphs of random ASes"
asn_srcs = random_ases.keys()
asn_srcs = list(set(asn_srcs))
for asn_src in asn_srcs:
    if not asn_src: continue
    if str(asn_src) in bgp_graphs: continue
    FNULL = open(os.devnull, 'w')
    proc = Popen(['mono',
                  BGPSIM_EXE_LOCATION,
                  '-server11002 ', AS_REL_CYCLOPS_FORMAT,
                  PRECOMP, EXIT_ASNS_BGPSIM],
                 stderr=subprocess.STDOUT)
    time.sleep(10)
    print "Getting all paths from", asn_src
    MESSAGE = asn_src + " -q"
    count = 0 
    for asn_dst in asn_dsts:
        MESSAGE += " " + asn_dst + " " + asn_src
        count += 1
    MESSAGE += " <EOFc> "
    print "Sending message to BGPSim to get %d paths from %s.." % (count, asn_src)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(MESSAGE)
    data = ""
    result = dict()
    buffer_size = 10000000
    while True:
        d = s.recv(buffer_size)
        data += d
        if len(d) == 0:
            break
        if "<EOFs>" in d:
            break

    s.close()
    proc.terminate()
    arr = data.split("-\n")
    gr = make_bgp_gr(arr, asn_src)
    bgp_graphs[asn_src] = gr


for asn, gr in bgp_graphs.iteritems():
    if not gr: continue
    try:
        data = json_graph.node_link_data( gr )
        s = json.dumps( data )
        with open(GRAPH_SIM_BGP + '%s' % asn, "w") as f:
            f.write( s )
    except:
        pdb.set_trace()
    
