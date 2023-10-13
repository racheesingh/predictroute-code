import time
import logging
import multiprocessing as mp
import traceback
from ripe.atlas.sagan import Result
import random
import radix
from networkx.readwrite import json_graph
import os
import csv
import networkx as nx
import mkit.inference.ip_to_asn as ip2asn
from urlparse import urlparse
import pdb
import urllib
import urllib2
import json
from datetime import datetime
from ripe.atlas.cousteau import (
    Traceroute,
    AtlasSource,
    AtlasCreateRequest,
    ProbeRequest,
    AtlasResultsRequest
)
import sys

if sys.argv[1] == 'adaptive':
    adaptive = True
else:
    adaptive = False
bgp_graphs_dir = "graph_bgp_sim/"

API_HOST = 'https://atlas.ripe.net'
API_MMT_URI = 'api/v1/measurement'
MSM_BUDGET = 10

private_addr_radix = radix.Radix()
private_adrs = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
for addr in private_adrs:
    private_addr_radix.add(addr)
    
def filter_cruft(data):
    if 'result' in data:
        res = data['result']
        for hop_idx, hop in enumerate( res ):
            if 'result' in hop:
                hop['result'] = [hr for hr in hop['result'] if 'edst' not in hr]
    return data

def get_probes_from_metadata(fname):
    with open(fname) as fi:
        probe_meta = json.load(fi)
    ripe_probes = {}        
    for pr in probe_meta['objects']:
        if 'system-ipv4-works' in pr['tags']:
            if pr['asn_v4'] in ripe_probes:
                ripe_probes[pr['asn_v4']].append(pr['id'])
            else:
                ripe_probes[pr['asn_v4']] = [pr['id']]
    return ripe_probes
ripe_probes = get_probes_from_metadata(RIPE_PROBES_METADATA)

if sys.argv[2] == 'top_content':
    all_prefs = []
    with open("data/per_prefix_count.csv") as fi:
        reader = csv.reader(fi)
        for row in reader:
            if row[0] == 'pref': continue
            if len(all_prefs) > 100: break
            all_prefs.append(row[0])
    pref_typ = "top_content"
elif sys.argv[2] == 'top_eyeball':
    with open("data/top_eyeball_prefs.json") as fi:
        all_prefs = json.load(fi)
    all_prefs = all_prefs.values()
    pref_typ = "top_eyeball"
elif sys.argv[2] == 'top_cust':
    with open("data/top_cust_cone_ips.json") as fi:
        all_prefs = json.load(fi)
    all_prefs = all_prefs.values()
    pref_typ = "top_cust"
else:
    with open("data/random_ips.json") as fi:
        all_prefs = json.load(fi)
    all_prefs = all_prefs.values()
    pref_typ = "random" 
                
def most_promising_measurement(gr, vantage_points):
    per_vp_gain = {}
    for vp_asn in vantage_points:
        if str(vp_asn) not in gr.node: continue
        gain_potential = 0
        gain_set = set()
        next_unseen_hop = [vp_asn]
        while True:
            if not next_unseen_hop:
                break
            if len(next_unseen_hop) > 1: pdb.set_trace()
            next_unseen_hop = next_unseen_hop[0]
            if 'seen' in gr.node[str(next_unseen_hop)] and gr.node[str(next_unseen_hop)]['seen']:
                break
            gain_potential += 1
            gain_set.add(str(next_unseen_hop))
            next_unseen_hop = gr.successors(str(next_unseen_hop))

        per_vp_gain[vp_asn] = (gain_potential, gain_set)
    most_promising = sorted(per_vp_gain.items(), key=lambda x:x[1][0], reverse=True)[0]
    return most_promising[0], most_promising[1][1]

def random_ip_in_pref(prefix):
    last_octet = random.randint(1,9)
    random_ip = '.'.join(prefix.split('.')[:-1] + [str(last_octet)])
    return random_ip

def run_trace(prefix, gr, vp_asn):
    source = AtlasSource(type="asn", value="%d" % vp_asn, requested=1)
    traceroute = Traceroute(
        af=4,
        target=random_ip_in_pref(prefix),
        description="pc-eval-max-coverage",
        protocol="ICMP",
    )
    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY_RS2,
        measurements=[traceroute],
        sources=[source],
        is_oneoff=True
    )
    (is_success, response) = atlas_request.create()
    return is_success, response

def get_gain(msm_id, gr, vp_asn, predicted_gain_set, adaptive=True):
    results = None
    while not results:
        is_success, results = AtlasResultsRequest(msm_id=msm_id).create()
        if not is_success: return 0
        
    traceroutes = []
    for result in results:
        data = filter_cruft(result)
        if 'result' in data:
            traceroutes.append(data)
    assert len(traceroutes) == 1
    
    iplinks = Result.get(traceroutes[0]).ip_path
    ases_seen = set()
    for ip_link_set in iplinks:
        ip = ip_link_set[0] # don't care about the ones after it
        if not ip: continue
        asn = ip2asn.ip2asn_bgp(ip)
        ases_seen.add(asn)
        
    if adaptive:
        for asn in ases_seen:
            if str(asn) in gr.node and 'seen' not in gr.node[str(asn)]:
                gr.node[str(asn)]['seen'] = True
    else:
        for asn in predicted_gain_set:
            if str(asn) in gr.node and 'seen' not in gr.node[str(asn)]:
                gr.node[str(asn)]['seen'] = True
                
    return ases_seen, gr

def get_coverage(gr):
    count = 0
    for node in gr.node:
        if 'seen' in gr.node[node]:
            count += 1
    return count

def adaptive_greedy(top_content_pref, gr):
    measurement_budget = MSM_BUDGET
    if adaptive:
        strategy = "adaptive"
    else:
        strategy = 'non-adaptive'

    fd = open("coverage/coverage_measurements_%s_%s.csv" % (top_content_pref, strategy), "a")
    fd.write("msm_num, prefix, covered, actual_covered, typ\n")
    vantage_points = ripe_probes.keys()
    actual_coverage_set = set()
    msm_num = 0
    while measurement_budget:
        vp_asn, predicted_gain_set = most_promising_measurement(gr, vantage_points)
        vantage_points.remove(vp_asn)
        print "Run trace:", top_content_pref, vp_asn
        trace_success, trace_result = run_trace(top_content_pref, gr, vp_asn)
        if not trace_success:
            print "Failed to measure from", vp_asn
            #if ['error']['errors'][0]['detail'] == \
            #   'You are not permitted to run more than 100 concurrent measurements.':
            time.sleep(20)
            print trace_result
            continue
        msm_num += 1
        msm_id = trace_result['measurements'][0]
        measurement_budget -= 1
        ases_seen, gr = get_gain(msm_id, gr, vp_asn, predicted_gain_set, adaptive=adaptive)
        actual_coverage_set = actual_coverage_set.union(ases_seen)
        if adaptive:
            print "%d,%s,%d,%s,%s\n" % \
                (msm_num, top_content_pref, get_coverage(gr), pref_typ, strategy)
            fd.write("%d,%s,%d,%s,%s\n" %
                     (msm_num, top_content_pref, get_coverage(gr), pref_typ,strategy))
        else:
            fd.write("%d,%s,%d,%d,%s,%s\n" %
                     (msm_num, top_content_pref, get_coverage(gr), len(actual_coverage_set),
                      pref_typ, strategy))
    fd.close()

def wrap_function(top_content_pref, gr):
    try:
        adaptive_greedy(top_content_pref, gr)
    except:
        pdb.set_trace()
        logging.warning( "".join(traceback.format_exception(*sys.exc_info())) )

pool = mp.Pool(processes=10, maxtasksperchild=1)
prefixes_covered = 0
for top_content_pref in all_prefs:
    if top_content_pref == '0.0.0.0': continue
    if private_addr_radix.search_best(top_content_pref):
        continue
    asn = ip2asn.ip2asn_bgp(top_content_pref)
    if not asn: continue
    if os.path.isfile(bgp_graphs_dir + asn):
        with open(bgp_graphs_dir + asn) as fi:
            jsonStr = json.load(fi)
        gr = json_graph.node_link_graph(jsonStr)
        
    if not gr.nodes(): continue
    print "Top content prefix", top_content_pref
    print "Prefix belongs to asn", asn
    prefixes_covered += 1
    if prefixes_covered > 25: break
    # pool.apply_async(wrap_function, args=(top_content_pref, gr,))
    adaptive_greedy(top_content_pref, gr)
pool.close()
pool.join()
pdb.set_trace()
