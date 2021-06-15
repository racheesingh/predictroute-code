from consts import *
import calendar
import dateutil.parser
import timeout_decorator
import bz2
import beanstalkc
import collections
import functools
import time
from urllib2 import HTTPError
from heapq import heappush, heappop
from itertools import count
import math
from operator import mul
import os
from graph_tool.all import *
import mkit.ripeatlas.probes as prb
from ripe.atlas.sagan import Result
import mkit.inference.ixp as ixp
import radix
from ripe.atlas.cousteau import Probe, Measurement
import pdb
import urllib2
import urllib
import mkit.inference.ip_to_asn as ip2asn
from ripe.atlas.cousteau import (
    Traceroute,
    AtlasSource,
    AtlasCreateRequest,
    ProbeRequest,
    AtlasResultsRequest
)
import random
import json
import csv
import glob
from settings import *
import datetime

GRAPHS_DIR = "decoy_dst_full_graphs/"
MAX_PATHS = 10
PER_SRC_DST_CUTOFF = 5

class memoized(object):
    '''Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    '''
    def __init__(self, func):
        self.func = func
        self.cache = {}
    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            # uncacheable. a list, for instance.
            # better to not cache than blow up.
            return self.func(*args)
        if args in self.cache:
            return self.cache[args]
        else:
            value = self.func(*args)
            self.cache[args] = value
            return value
    def __repr__(self):
        '''Return the function's docstring.'''
        return self.func.__doc__
    def __get__(self, obj, objtype):
        '''Support instance methods.'''
        return functools.partial(self.__call__, obj)
    
@memoized
def build_rtree(fname):
    rtree_bgpv4 = radix.Radix()
    asn_to_prefs ={}
    print "Making radix tree for routing table with", fname
    with open(fname) as fi:
        for line in fi:
            ip, preflen, asn = line.split()
            if asn in asn_to_prefs:
                asn_to_prefs[asn].append("%s/%s" % (ip, preflen))
            else:
                asn_to_prefs[asn] = ["%s/%s" % (ip, preflen)]
            if ',' in asn:
                tokens = asn.split(',')
                asn = tokens[0]
            if '_' in asn:
                tokens = asn.split('_')
                asn = tokens[0]
            rnode = rtree_bgpv4.add(network=ip, masklen=int(preflen))
            rnode.data["asn"] = asn
            
    return rtree_bgpv4

# Want to finish building the most recent radix tree once
# to keep the runtime of the vanilla ip2asn_bgp_ts the same
# as before.
pfx2asn_files = os.listdir(PFX2ASN_DIR)
pfx2asn_files = [PFX2ASN_DIR + fname for fname in pfx2asn_files]
newest = max(pfx2asn_files , key = os.path.getctime)
most_recent_rtree = build_rtree(newest)

@memoized
def get_rtree(ts):
    if not ts:
        rtree = most_recent_rtree
    else:
        ts_dt = datetime.datetime.fromtimestamp(ts)
        year = str(ts_dt.year)
        if ts_dt.day < 10:
            day = "0%d" % ts_dt.day
        else:
            day = "%d" % ts_dt.day
            
        if ts_dt.month < 10:
            month = "0%d" % ts_dt.month
        else:
            month = "%d" % ts_dt.month
            
        fname = PFX2ASN_DIR + "routeviews-rv2-%s%s%s*" % (year, month, day)
        fname = glob.glob(fname)
        
        if not fname:
            return most_recent_rtree
        
        assert len(fname) == 1
        fname = fname[0]
        rtree = build_rtree(fname)
        
    return rtree

def ip2asn_bgp_ts(ip, ts=None):
    rtree = get_rtree(ts)
    try:
        node = rtree.search_best(ip)
    except ValueError:
        print "Could not get AS for IP", ip
        return None
    if node:
        return node.data['asn']
    return None

def ip2pref_bgp_ts(ip, ts=None):
    rtree = get_rtree(ts)
    try:
        node = rtree.search_best(ip)
    except ValueError:
        print "Could not get PREF for IP", ip
        return None
    if node:
        return node.prefix.replace('/', '_')
    return None
    
class PathBuffer(object):
    def __init__(self):
        self.paths = set()
        self.sortedpaths = list()
        self.counter = count()
        
    def __len__(self):
        return len(self.sortedpaths)
    
    def push(self, cost, path):
        hashable_path = tuple(path)
        if hashable_path not in self.paths:
            heappush(self.sortedpaths, (cost, next(self.counter), path))
            self.paths.add(hashable_path)
        
    def pop(self):
        (cost, num, path) = heappop(self.sortedpaths)
        hashable_path = tuple(path)
        self.paths.remove(hashable_path)
        return path
        
def get_probes_from_metadata(fname):
    with open(fname) as fi:
        probe_meta = json.load(fi)
    ripe_probes = {}        
    for pr in probe_meta['objects']:
        if 'system-ipv4-works' in pr['tags']:
            if  not pr['asn_v4']: continue
            if pr['asn_v4'] in ripe_probes:
                ripe_probes[pr['asn_v4']].append(pr['id'])
            else:
                ripe_probes[pr['asn_v4']] = [pr['id']]
    return ripe_probes

ripe_probes = get_probes_from_metadata(RIPE_PROBE_METADATA)
def get_sources():
    sources = []
    for asn in ripe_probes:
        source = AtlasSource(type="asn", value="%d" % asn, requested=1,
                             tags={"include":["system-ipv4-works"]})
        sources.append(source)
    return sources

def random_ip_in_pref(prefix):
    last_octet = random.randint(1,254)
    random_ip = '.'.join(prefix.split('.')[:-1] + [str(last_octet)])
    return random_ip

def run_trace_from_all_ripe(ip_in_prefix, sources, in_parts=False):
    # sources = get_sources()
    traceroute = Traceroute(
        af=4,
        target=ip_in_prefix,
        description="pceval",
        protocol="ICMP"
    )
    
    if in_parts:
       measurement_ids = []
       for i in range(0,4):
           sources_chunk = sources[1000*i: 1000*(i+1)]
           atlas_request = AtlasCreateRequest(
               start_time=datetime.datetime.utcnow() + datetime.timedelta(minutes=1),
               key=ATLAS_API_KEY_PG,
               measurements=[traceroute],
               sources=sources_chunk,
               is_oneoff=True
           )
           print "Running traces to %s from %d probes" % (prefix, len(sources_chunk))
           (is_success, response) = atlas_request.create()
           if not is_success:
               print "Failed to measure prefix %s (round %d)" % (pref, i)
               print response
               continue
           msm_id = response['measurements'][0]
           measurement_ids.append(msm_id)
    else:
        atlas_request = AtlasCreateRequest(
            start_time=datetime.datetime.utcnow() + datetime.timedelta(minutes=2),
            key=ATLAS_API_KEY_RS,
            measurements=[traceroute],
            sources=sources,
            is_oneoff=True,
            packets=1
        )
        print "Running traces to %s from %d probes" % (ip_in_prefix, len(sources))
        (is_success, response) = atlas_request.create()
        if not is_success:
            print "Failed to measure IP", ip_in_prefix
            print response
            return []
        msm_id = response['measurements'][0]
        print ip_in_prefix, msm_id
        measurement_ids = [msm_id]
        
    return measurement_ids

orgs = {}
with open(CAIDA_AS2ORG, "rb") as f:
    for line in f:
        # ignore commented lines
        if line[0] == "#":
            continue
        tokens = line.rstrip().split('|')
        # aut|changed|name|org_id|source
        if tokens[0].isdigit():
            asn = int(tokens[0])
            orgs[asn] = tokens[3]

def are_siblings(as1, as2):
    as1 = int(as1)
    as2 = int(as2)
    # print "Checking if siblings:", as1, as2
    if as1 not in orgs or as2 not in orgs:
        return False
    return orgs[ as1 ] == orgs[ as2 ]

def filter_cruft(data):
    if 'result' in data:
        res = data['result']
        for hop_idx, hop in enumerate( res ):
            if 'result' in hop:
                hop['result'] = [hr for hr in hop['result'] if 'edst' not in hr]
    return data

def parse_mmt(msm_id, start=None, end=None):
    if start and end:
        kwargs = {"msm_id": msm_id, "start": start, "stop": end}
    else:
        kwargs = {"msm_id": msm_id}
    is_success, results = AtlasResultsRequest(**kwargs).create()
    traceroutes = []
    for result in results:
        data = filter_cruft(result)
        if 'result' in data:
            traceroutes.append(data)
    return traceroutes

ixp_radix = ixp.ixp_radix
private_addr_radix = radix.Radix()
private_adrs = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
for addr in private_adrs:
    private_addr_radix.add(addr)

def getlinktype( numASHop1, numASHop2 ):
    if numASHop2 - numASHop1 > 1:
        return 'i'
    return 'd'

def parse_traceroute(iplinks, src_asn):
    aslinks = {'_nodes': set(), '_links': [] }
    last_resp_hop_nr = None
    last_resp_hop_ases = set()
    this_hop_ases = None
    pdb.set_trace()
    for nbr, hop in enumerate(iplinks.ip_path):
        if this_hop_ases and len(this_hop_ases) > 0:
            last_resp_hop_ases = this_hop_ases
            last_resp_hop_nr = this_resp_hop_nr
            
        this_resp_hop_nr = nbr
        ips = set()
        for ip in hop:
            if ip:
                ips.add(ip)
        this_hop_ases = set()
        for ip in ips:
            if private_addr_radix.search_best(ip):
                continue
            asn = ip2asn_bgp_ts(ip)
            if asn:
                this_hop_ases.add(asn)

        # Only care about the first AS, don't know if there are more >.<
        this_hop_ases = list(this_hop_ases)[:1]
        if len(this_hop_ases) == 1 and len(last_resp_hop_ases) == 1:
            this_asn = list(this_hop_ases)[0]
            last_asn = list(last_resp_hop_ases)[0]
            if this_asn != last_asn:
                ixps = [ixp_radix.search_best(x) for x in ips]
                if any(ixps) or str(this_asn) in ixp.IXPs:
                    if '_ixps' in aslinks:
                        aslinks['_ixps'].append((this_asn, ip))
                    else:
                        aslinks['_ixps'] = [(this_asn, ip)]
                link_type = getlinktype(last_resp_hop_nr, this_resp_hop_nr)
                link = { 'src': last_asn,
                         'dst': this_asn, 'type': link_type }
                aslinks['_nodes'].add( this_asn )
                aslinks['_nodes'].add( last_asn )
                aslinks['_links'].append( link )

        elif len(this_hop_ases) == 0 or len(last_resp_hop_ases) == 0:
            pass # uninteresting
        else:
            # Different ASes at a hop, ignoring such traceroutes
            print "Uncaught situation at hop no %s->%s: %s->: %s" % \
                ( last_resp_hop_nr, this_resp_hop_nr , last_resp_hop_ases, this_hop_ases )
            continue
    if not aslinks['_links']:
        return aslinks
        
    # Many times, the first hop address is a local (non-routable) prefix, so
    # prepending src_asn to the AS level path since we know for sure that the traceroute
    # originated from src_asn
    if src_asn:
        if aslinks['_links'][0]['src'] != str(src_asn):
            aslinks['_nodes'].add(src_asn)
            aslinks['_links'] = [{'src':str(src_asn),
                                  'dst':aslinks['_links'][0]['src'], 'type':'i'}] + \
                aslinks['_links']
    
    # This code block short circuits paths like A->B->C->B->D to A->B->D
    # Also A->B->A->C->D should become A->C->D.
    linkssane = []
    delnext = False
    for index in range(len(aslinks['_links'])):
        if delnext:
            delnext = False
            continue
        if (index + 1) < len(aslinks['_links']):
            if aslinks['_links'][index]['src'] == aslinks['_links'][index+1]['dst']:
                delnext = True
            else:
                linkssane.append(aslinks['_links'][index])
        else:
            linkssane.append(aslinks['_links'][index])
            
    loopdetect = []
    for link in linkssane:
        loopdetect.append(link['src'])
    loopdetect.append(link['dst'])
    loops = [i for i,x in enumerate(loopdetect) if loopdetect.count(x) > 1]
    if loops:
        # Cannot trust this traceroute, it has loops
        aslinks['_links'] = []
        return aslinks
    
    aslinks['_links'] = linkssane
    return aslinks

def is_continuous(links):
    for i in range(len(links)-1):
        if links[i]['dst'] != links[i+1]['src']:
            return False
    return True

def reached_dst(links, dst_asn, dst_bgp_pfx):
    reached_dst_asn = False
    reached_dst_bgp_pfx = False
    dst_asn_at = []
    dst_bgp_pfx_at = []
    link_count = 0
    for link in links:
        if link['dst']['asn'] == str(dst_asn) or link['src']['asn'] == str(dst_asn):
            if link_count - 1 not in dst_asn_at:
                dst_asn_at.append(link_count)
            reached_dst_asn = True

        if link['dst']['bgp_pfx'] == dst_bgp_pfx or link['src']['bgp_pfx'] == dst_bgp_pfx:
            if link_count - 1 not in dst_bgp_pfx_at:
                dst_bgp_pfx_at.append(link_count)
            reached_dst_bgp_pfx = True
        link_count += 1

    return reached_dst_asn, dst_asn_at, reached_dst_bgp_pfx, dst_bgp_pfx_at

# def has_loop(links):
#     hops = []
#     for link in links:
#         if link['dst'] in hops: return True
#         hops.append(link['dst'])
#     return False

def get_raw_trace_str(iplinks):
    path_str = ""
    for hop in iplinks:
        if not hop: continue
        hop_str = "-".join([x for x in hop if x]) + "|"
        path_str = path_str + hop_str
    # Removing the last |
    path_str = path_str[:-1]
    return path_str

def parse_traceroute_v2(iplinks, granularity="asn"):
    nodelinks = {'_nodes': [], '_links': [] }
    last_resp_hop_nr = None
    last_resp_hops = set()
    this_resp_hops = None
    for nbr, hop in enumerate(iplinks.ip_path):
        if this_resp_hops and len(this_resp_hops) > 0:
            last_resp_hops = this_resp_hops
            last_resp_hop_nr = this_resp_hop_nr
            
        this_resp_hop_nr = nbr
        ips = set([x for x in hop if x])

        this_resp_hops = []
        for ip in ips:
            # If this is a private IP, let us not try to
            # resolve it to its prefix/ASN. We skip this.
            if private_addr_radix.search_best(ip):
                # Early parts of the trace might have private addresses
                continue
            
            all_gran_hop = {}
            asn = ip2asn_bgp_ts(ip)
            bgp_pfx = ip2pref_bgp_ts(ip)
            if not asn and not bgp_pfx:
                # print "This hop has neither a BGP prefix nor an ASN, skip", ip
                continue
            pfx = ".".join(ip.split('.')[:-1] + ['0'])
            all_gran_hop['asn'] = asn
            all_gran_hop['bgp_pfx'] = bgp_pfx
            all_gran_hop['pfx'] = pfx
            if all_gran_hop not in this_resp_hops:
                this_resp_hops.append(all_gran_hop)

        # Only care about the first hop, assuming the rest are same
        # Unsure if this is true at /24 level
        if this_resp_hops:
            this_resp_hops = [this_resp_hops[0]]
        if len(this_resp_hops) == 1 and len(last_resp_hops) == 1:
            this_hop = list(this_resp_hops)[0]
            last_hop = list(last_resp_hops)[0]
            # To decide if this is the same node or different, check
            # if the granularity attribute has changed
            if this_hop[granularity] != last_hop[granularity]:
                if is_ixp(this_hop['asn'], this_hop['bgp_pfx']):
                    if '_ixps' not in nodelinks:
                        nodelinks['_ixps'] = [this_hop]
                    else:
                        nodelinks['_ixps'].append(this_hop)
                        
                link_type = getlinktype(last_resp_hop_nr, this_resp_hop_nr)
                link = {'src': last_hop,
                         'dst': this_hop, 'type': link_type}
                nodelinks['_nodes'].append(this_hop)
                nodelinks['_nodes'].append(last_hop)
                nodelinks['_links'].append(link)

        elif len(this_resp_hops) == 0 or len(last_resp_hops) == 0:
            pass
        else:
            # Different ASes at a hop, ignoring such traceroutes
            assert False, "This shouldn't happen because I am picking the first hop explicitly"
            print "Uncaught situation at hop no %s->%s: %s->: %s" % \
                (last_resp_hop_nr, this_resp_hop_nr , last_resp_hops, this_resp_hops)
            continue
        
    if not nodelinks['_links']:
        return nodelinks
        
    links_new = nodelinks['_links']
    while exists_one_hop_cycle(links_new, granularity):
        links_new, removed_cycle_count = short_circuit_one_hop_cycles(links_new, granularity)
        if not links_new:
            break
    linkssane = links_new
    
    if linkssane and has_cycles(linkssane, granularity):
        nodelinks['_links'] = []
        return nodelinks
    
    nodelinks['_links'] = linkssane
    return nodelinks

def has_cycles(links, granularity):
    loopdetect = []
    for link in links:
        loopdetect.append(link['src'][granularity])
    loopdetect.append(link['dst'][granularity])
    loops = [i for i,x in enumerate(loopdetect) if loopdetect.count(x) > 1]
    
    if loops:
        # print "Cannot trust this traceroute, it has loops", loopdetect
        return True
    return False
    
def exists_one_hop_cycle(links, granularity):
    loopdetect = []
    for link in links:
        loopdetect.append(link['src'][granularity])
    loopdetect.append(link['dst'][granularity])
    
    loops = [i for i,x in enumerate(loopdetect) if loopdetect.count(x) > 1]
    if not loops: return False
    repeated_hops = list(set([loopdetect[x] for x in loops]))

    for rep_hop in repeated_hops:
        occurences_of_rep_hop = [i for i, x in enumerate(loopdetect) if x == rep_hop]
        for loop_ind_1, loop_ind_2 in zip(occurences_of_rep_hop, occurences_of_rep_hop[1:]):
            if loop_ind_2 - loop_ind_1 == 2:
                return True
    return False
        
def short_circuit_one_hop_cycles(links, granularity):
    linkssane = []
    delnext = False
    removed_cycles = 0
    for index in range(len(links)):
        if delnext:
            delnext = False
            removed_cycles += 1
            continue
        if (index + 1) < len(links):
            if links[index]['src'][granularity] == \
               links[index+1]['dst'][granularity]:
                delnext = True
            else:
                linkssane.append(links[index])
        else:
            linkssane.append(links[index])
            
    return linkssane, removed_cycles

    
API_HOST = "https://atlas.ripe.net:443"
API_MMT_URI = 'api/v2/measurements/traceroute'

def init_graph():
    # Create a graph
    
    # Each node will have these properties: which ASN, which BGP pref, /24 pref
    # traces generated from that node, the exact path seen from that node (if traces
    # were generated there), if the node is an IXP.
    G = Graph()
    gran_prop = G.new_graph_property("string")
    G.gp.granularity = gran_prop
    
    ## VERTEX PROPERTIES
    vprop_asn = G.new_vertex_property("string")
    G.vp.asn = vprop_asn
    
    # BGP prefix to which this node belongs
    vprop_bgp_prefix = G.new_vertex_property("string")
    G.vp.bgp_pfx = vprop_bgp_prefix

    # /24 prefix to which this node belongs
    vprop_prefix = G.new_vertex_property("string")
    G.vp.pfx = vprop_prefix

    # Which source of measurement led to this node's discovery
    vprop_mmt_type = G.new_vertex_property("string", val="")
    G.vp.mmt_type = vprop_mmt_type

    # How many traces originated here?
    vprop_gen = G.new_vertex_property("int", val=0)
    G.vp.generated = vprop_gen

    # If this node generated a trace, what was the exact path seen?
    # Separate multiple paths by semicolon
    vprop_path_str = G.new_vertex_property("string", val="")
    G.vp.str_path = vprop_path_str
   
    # Is this node part of an IXP?
    vprop_ixp = G.new_vertex_property("boolean")
    G.vp.ixp = vprop_ixp

    # EDGE PROPERTIES
    # Edge learned via what kind of measurement?
    eprop_type = G.new_edge_property("short")
    G.ep.type = eprop_type

    # Measurement ID
    # eprop_msm = G.new_edge_property("long")
    # G.ep.msm = eprop_msm

    # Which source probe did we measure this edge from?
    # eprop_probe = G.new_edge_property("int")
    # G.ep.probe = eprop_probe

    # Origin dictionary, keeps track of traces that traverse this edge,
    # where did they come from (previous edge)
    eprop_dict = G.new_edge_property("object")   
    G.ep.origin = eprop_dict

    # Timestamp of the earliest measurement we learned this edge
    eprop_ts = G.new_edge_property("int64_t")
    G.ep.start_ts = eprop_ts

    # Timestamp of the latest measurement where we learned this edge
    eprop_ts = G.new_edge_property("int64_t")
    G.ep.last_ts = eprop_ts

    return G


@timeout_decorator.timeout(100)
def combine_dags(gr1, gr2, node_gran, dst_iden_attr):
    remove_parallel_edges(gr1)
    remove_parallel_edges(gr2)
    remove_self_loops(gr1)
    remove_self_loops(gr2)
    
    vertices_match_1 = find_vertex(gr1, gr1.vp[node_gran], dst_iden_attr)
    vertices_match_2 = find_vertex(gr2, gr2.vp[node_gran], dst_iden_attr)
    assert len(vertices_match_1) == 1
    assert len(vertices_match_2) == 1
    root_node_1 = vertices_match_1[0]
    root_node_2 = vertices_match_2[0]

    # gr_new is a copy of gr1
    gr_new = gr1.copy()
    # copy over all vertices from gr2
    for v1 in gr2.vertices():
        v = create_new_node(gr_new, gr2.vp.asn[v1], gr2.vp.bgp_pfx[v1],
                            gr2.vp.pfx[v1], iden_type=node_gran)
        gr_new.vp.generated[v] += gr2.vp.generated[v1]
        gr_new.vp.str_path[v] += gr2.vp.str_path[v1]

    for e1 in gr2.edges():
        e_src = e1.source()
        e_src_iden_attr = gr2.vp[node_gran][e_src]
        e_dst = e1.target()
        e_dst_iden_attr = gr2.vp[node_gran][e_dst]
        # both src and dst should be in gr_new
        # but is the edge in there?        
        gr_new_src = find_vertex(gr_new, gr_new.vp[node_gran], e_src_iden_attr)
        assert len(gr_new_src) == 1
        gr_new_src = gr_new_src[0]
        gr_new_dst = find_vertex(gr_new, gr_new.vp[node_gran], e_dst_iden_attr)
        assert len(gr_new_dst) == 1
        gr_new_dst = gr_new_dst[0]
        edge = gr_new.edge(gr_new_src, gr_new_dst)
        if not edge:
            edge = gr_new.add_edge(gr_new_src, gr_new_dst)
                    
        # merge origin
        if gr2.ep.origin[e1]:
            for or_key in gr2.ep.origin[e1]:
                # or_key is a UTC timestamp
                assert isinstance(or_key, int)
                if not gr_new.ep.origin[edge]:
                    gr_new.ep.origin[edge] = {}
                if or_key in gr_new.ep.origin[edge]:
                    for edge_key in gr2.ep.origin[e1][or_key]:
                        if node_gran == 'bgp_pfx':
                            assert '_' in edge_key or edge_key == 'gen' or edge_key == 'unknown'
                        if edge_key in gr_new.ep.origin[edge][or_key]:
                            gr_new.ep.origin[edge][or_key][edge_key] += \
                                                gr2.ep.origin[e1][or_key][edge_key]
                        else:
                            gr_new.ep.origin[edge][or_key][edge_key] =\
                                                gr2.ep.origin[e1][or_key][edge_key]
                else:
                    gr_new.ep.origin[edge][or_key] = gr2.ep.origin[e1][or_key]
                    
        # # merge super_origin
        # if gr2.ep.super_origin[e1]:
        #     for or_key in gr2.ep.super_origin[e1]:
        #         assert '_' in or_key or or_key == 'gen'
        #         if not gr_new.ep.super_origin[edge]:
        #              gr_new.ep.super_origin[edge] = {}
        #         if or_key in gr_new.ep.super_origin[edge]:
        #             gr_new.ep.super_origin[edge][or_key] += gr2.ep.super_origin[e1][or_key]
        #         else:
        #            gr_new.ep.super_origin[edge][or_key] = gr2.ep.super_origin[e1][or_key]
                    
        # set start_ts and last_ts
        if not gr_new.ep.start_ts[edge]:
            gr_new.ep.start_ts[edge] = gr2.ep.start_ts[e1]
        if not gr_new.ep.last_ts[edge]:
            gr_new.ep.last_ts[edge] = gr2.ep.last_ts[e1]

        if gr2.ep.start_ts[e1] < gr_new.ep.start_ts[edge]:
            gr_new.ep.start_ts[edge] = gr2.ep.start_ts[e1]
        
        if gr2.ep.last_ts[e1] > gr_new.ep.last_ts[edge]:
            gr_new.ep.last_ts[edge] = gr2.ep.last_ts[e1]

        assert gr_new.ep.start_ts[edge] <= gr_new.ep.last_ts[edge]
        
    return gr_new

'''
Create a node of type iden_type if it does not exist already. If it
does, update its attributes.
'''
def create_new_node(gr, asn, bgp_pfx, pfx, iden_type='asn'):
    if asn:
        asn = str(asn)
    if bgp_pfx:
        assert '_' in bgp_pfx
        
    if iden_type == 'asn':
        iden = asn
        remaining_node_attrs = {'bgp_pfx': bgp_pfx, 'pfx': pfx}
    elif iden_type == 'bgp_pfx':
        iden = bgp_pfx
        remaining_node_attrs = {'asn': asn, 'pfx': pfx}
    else:
        assert iden_type == 'pfx'
        iden = pfx
        remaining_node_attrs = {'asn': asn, 'bgp_pfx': bgp_pfx}
        
    assert iden_type in gr.vp
    vertices_match = find_vertex(gr, gr.vp[iden_type], iden)
    
    if len(vertices_match) > 0:
        assert len(vertices_match) == 1
        v = vertices_match[0]
        try:
            assert gr.vp[iden_type][v] == iden
        except AssertionError:
            pdb.set_trace()
    else:
        v = gr.add_vertex()
        gr.vp[iden_type][v] = iden

    for attr in remaining_node_attrs:
        if not gr.vp[attr][v]:
            gr.vp[attr][v] = remaining_node_attrs[attr]
        else:
            if attr == 'asn':
                # assert remaining_node_attrs[attr] == gr.vp[attr][v]
                # This really doesn't make sense, there should be
                # just one AS associated with a BGP PFX or /24
                # But since shit happens on the Internet all the damn time,
                # I have seen this happen.
                existing_asns = gr.vp['asn'][v].split(';')
                if remaining_node_attrs[attr] not in existing_asns:
                    gr.vp[attr][v] += ';%s' % remaining_node_attrs[attr]
            elif attr == 'bgp_pfx' and iden == 'asn':
                existing_bgp_pfxes = gr.vp[attr][v].split(';')
                if bgp_pfx not in existing_bgp_pfxes:
                    gr.vp[attr][v] += ';%s' % bgp_pfx
            elif attr == 'bgp_pfx' and iden == 'pfx':
                assert remaining_node_attrs[attr] == gr.vp[attr][v]
            elif attr == 'pfx' and pfx:
                existing_pfxes = gr.vp[attr][v].split(';')
                if pfx not in existing_pfxes:
                    gr.vp[attr][v] += ';%s' % pfx
                
    return v

def is_ixp(asn, pfx):
    if str(asn) in ixp.IXPs: return True
    # If the BGP prefix of the node is a superset of IXP prefixes?
    if ixp_radix.search_covered(pfx.replace('_', '/')): return True
    # If the BGP prefix of the node is a subset of the IXP prefixes?
    if ixp_radix.search_best(pfx.split('_')[0]): return True
    return False
    
def add_node_to_nodelinks(links, nodes, node, position="front"):
    if position == "front":
        nodes = [node] + nodes
        dst_node = links[0]['src']
        new_link = {'src': node, 'dst': dst_node, 'type': 'i'} # always assume indirect
        links = [new_link] + links
        return links, nodes
    assert False, "Unrecognized position"

def remove_ixps(nodelinks):
    links = nodelinks['_links']
    identified_ixps = nodelinks['_ixps']
    new_links = []
    connecting_link = {}

    for link in links:
        if link['dst'] in identified_ixps:
            if 'src' not in connecting_link and link['src'] not in identified_ixps:
                connecting_link['src'] = link['src']
        elif link['src'] in identified_ixps:
            if link['dst'] not in identified_ixps and 'dst' not in connecting_link:
                connecting_link['dst'] = link['dst']
        else:
            new_links.append(link)
        if 'src' in connecting_link and 'dst' in connecting_link:
            connecting_link['type'] = 'i'
            new_links.append(connecting_link)
            connecting_link = {}

    nodes = [node for node in nodelinks['_nodes'] if node not in identified_ixps]
    return {'_nodes': nodes, '_links': new_links, '_ixps': []}

def does_target_match(trace_target, node_gran, dag_target):
    # trace_target is an IP address
    trace_target_asn = ip2asn_bgp_ts(trace_target)
    trace_target_bgp_pfx = ip2pref_bgp_ts(trace_target)
    if not trace_target_asn or not trace_target_bgp_pfx or not dag_target:
        return False
    #"Can't send non-existent targets %s %s %s %s" % (trace_target, dag_target,
    #                                                  trace_target_asn,
    #                                                  trace_target_bgp_pfx)
    if node_gran  == 'asn':
        if int(trace_target_asn) == int(dag_target):
            return True
    elif node_gran == 'bgp_pfx':
        if trace_target_bgp_pfx == dag_target:
            return True
    else:
        assert node_gran == 'pfx'
        if ".".join(trace_target.split('.')[:-1]) == ".".join(dag_target.split(".")[:-1]):
            return True
    print "Trace target: %s and DAG target: %s" % (trace_target_bgp_pfx, dag_target)
    return False

# These are IPv4 DNS Ninja measurement IDs
dns_ninja_msms = [1789781, 2024335, 2444159]

def get_ninja_traces(msm_id, start_time, end_time):
    data = parse_mmt(msm_id, start=start_time, end=end_time)
    return data

def get_pref_asn(ip, ts=None):
    dst_prefix = ".".join(ip.split('.')[:-1] + ['0'])
    dst_asn = ip2asn_bgp_ts(ip, ts=ts)
    # if not dst_asn:
    #    print "No ASN for this IP", ip
    dst_bgp_pref = ip2pref_bgp_ts(ip, ts=ts)
    # if not dst_bgp_pref:
    #     maybe_dst_bgp_pref = ip2pref_bgp_ts(ip)
    #     if maybe_dst_bgp_pref:
    #         dst_bgp_pref = maybe_dst_bgp_pref
    #         dst_asn = ip2asn_bgp_ts(ip)
    # if not dst_bgp_pref:
    #    print "No BGP prefix for this IP", ip
    return dst_prefix, dst_bgp_pref, dst_asn

def get_msms(dst_asn, ts, mmt_window_hours=24):
    # Narrow by destination ASN because don't know of a way to narrow by
    # destination prefix
    endtime_demarcation = None
    if ts:
        endtime_demarcation = ts
    else:
        endtime_demarcation = ts - 3600*mmt_window_hours

    offset = 0
    msms_all = []
    while True:
        offset += 1
        if dst_asn:
            api_args = dict(target_asn=dst_asn, status=4, page=offset,
                            type="traceroute", af=4, stop_time_gte=endtime_demarcation)
        else:
            api_args = dict(status=4, page=offset,
                            type="traceroute", af=4, stop_time_gte=endtime_demarcation)

        url = "%s/%s/?%s" % (API_HOST, API_MMT_URI, urllib.urlencode(api_args))
        try:
            response = urllib2.urlopen(url)
            data = json.load(response)
            if 'results' not in data:
                break
            for d in data['results']:
                msms_all.append(d['id'])
        except HTTPError:
            print "Failed URL", url
            break

    return msms_all

def get_iden_attr(asn, bgp_pfx, pfx, node_gran):
    iden_attr= None
    if node_gran == 'asn':
        iden_attr = asn
    elif node_gran == 'bgp_pfx':
        iden_attr = bgp_pfx
    else:
        assert node_gran == 'pfx', node_gran
        iden_attr = pfx
    return iden_attr

def span_match(start, end, baseline_start, baseline_end):
    if start < baseline_start and end > baseline_start:
        return True
    if start > baseline_start and end < baseline_end:
        return True
    if start < baseline_end and end > baseline_end:
        return True
    return False
    
def is_intersection_time(mmt_start, mmt_end, ts, period):
    ts_end = ts + 3600*period
    return span_match(mmt_start, mmt_end, ts, ts_end)

ases_where_traces_go_to_die = set()
'''This method lets you construct a DAG for an IP address at
either ASN or BGP prefix granularity. You can pass it MSMs of your choice
and/or let it search for the measurements.'''
def compute_dest_based_graphs(dst_ip,
                              dag_dict={}, node_gran='bgp_pfx', msms=None, ts=None,
                              allow_discts_trace=True, remove_ixp_all=False,
                              search_for_msms=False, periodic_mmt_window_hrs=24, ninja=False,
                              ninja_mmt_window_hrs=24,
                              mmt_search_window_hrs=24,
                              global_dst_iden_attr=None):
    '''
    1. root_node_gran an take 4 values: 'pfx', 'bgp_pfx', 'bgp_atom', 'asn'
    Similarly, inter_node_gran can the same 4 value.
    2. msms should be a list.
    3. dag_dict: Dictionary consisting of identifier (pfx or asn) to DAG objects.
    This allows incrementally adding to the DAGs in successive calls to this function.
    '''
    assert ts
    if ts == 0:
        ts = None
        
    if not search_for_msms and not msms and not ninja:
        assert False, "No measurement IDs passed, search not enabled, nothing to do."

    global_dst_pfx, global_dst_bgp_pfx, global_dst_asn = None, None, None
    if dst_ip and not global_dst_iden_attr:
        global_dst_ip = dst_ip
        print "Making a DAG for", global_dst_ip
        global_dst_pfx, global_dst_bgp_pfx, global_dst_asn = get_pref_asn(dst_ip, ts)
        if not global_dst_bgp_pfx or not global_dst_asn:
            print "Global destination ASN/PFX not known for IP", dst_ip
            return dag_dict, 0, 0
        if remove_ixp_all and is_ixp(global_dst_asn, global_dst_bgp_pfx):
            print "This destination is an IXP and rempve_ixp_all flag is on, bailing ASAP", \
                global_dst_asn, global_dst_bgp_pfx
            return dag_dict, 0, 0
        global_dst_iden_attr = get_iden_attr(global_dst_asn, global_dst_bgp_pfx,
                                             global_dst_pfx, node_gran)
    else:
        rtree = get_rtree(ts)
        if node_gran == 'bgp_pfx':
            rnode = rtree.search_exact(global_dst_iden_attr.replace('_', '/'))
            if not rnode:
                print "No node found in radix tree, this is madness"
                return dag_dict, 0, 0
            global_dst_asn = rnode.data['asn']
            global_dst_bgp_pfx = global_dst_iden_attr
            global_dst_pfx = None
        elif node_gran == 'asn':
            global_dst_asn = global_dst_iden_attr
            global_dst_bgp_pfx = None
            global_dst_pfx = None            

    if not msms:
        msms_all = []
    else:
        msms_all = msms

    if search_for_msms:
        # by default gets measurements in a 24 hour window from the timestamp ts
        msms_all.extend(get_msms(global_dst_asn, ts, mmt_window_hours=mmt_search_window_hrs))

    msms_all = list(set(msms_all))
    if ninja:
        msms_all.extend(dns_ninja_msms)
        
    total_trace_count = 0
    true_trace_count = 0     
    for msm in msms_all:
        info = Measurement(id=int(msm)).meta_data
        
        if not info['is_oneoff'] and not is_intersection_time(info['start_time'], info['stop_time'],
                                                              ts, periodic_mmt_window_hrs):
            continue
        if info['af'] != 4: continue
        if info['probes_scheduled'] == 0:
            continue
        if msm in dns_ninja_msms:
            if ts:
                # For DNS Ninja, get only one day worth of traces
                start_time = ts
                end_time = ts + (ninja_mmt_window_hrs*3600) 
            else:
                start_time = int(time.time()) - (ninja_mmt_window_hrs*3600)
                end_time = int(time.time())
            data = parse_mmt(msm, start=start_time, end=end_time)
            
        elif not info['is_oneoff']:
            if ts:
                start = ts
                end = ts + (periodic_mmt_window_hrs * 3600)
            else:
                end = int(time.time())
                start = end - (periodic_mmt_window_hrs * 3600)
            data = parse_mmt(msm, start=start, end=end)
        else:
            data = parse_mmt(msm)

        for d in data:
            trace_endtime =  d['endtime']
            trace_hour_count = datetime.datetime.fromtimestamp(trace_endtime).hour
            # Error in any hop of the trace, skip
            error = [x for x in d['result'] if 'error' in x]
            if error:
                continue
            try:
                measurement_target = d['dst_addr']
            except KeyError:
                continue
            
            dst_pfx, dst_bgp_pfx, dst_asn = get_pref_asn(measurement_target, ts)
            if not dst_bgp_pfx or not dst_asn: continue
            
            if is_ixp(dst_asn, dst_bgp_pfx):
                if remove_ixp_all:
                    print "Dst is an IXP and rempve_ixp_all flag is on, bailing ASAP", \
                        dst_asn, dst_bgp_pfx
                    continue

            dst_iden_attr = get_iden_attr(dst_asn, dst_bgp_pfx, dst_pfx, node_gran)
            #if dst_ip and not does_target_match(measurement_target, node_gran,
            #                                    global_dst_iden_attr):
            if dst_ip and global_dst_iden_attr != dst_iden_attr:
                print "The target of this mmt does not match the target of the DAG, skipping", \
                    global_dst_iden_attr, dst_iden_attr
                continue
            
            if dst_iden_attr not in dag_dict:
                G = init_graph()
                G.gp.granularity = node_gran
            else:
                G = dag_dict[dst_iden_attr]
                
            root_node = create_new_node(G, dst_asn, dst_bgp_pfx, dst_pfx, node_gran)
            
            total_trace_count += 1
            
            src_asn = prb.get_probe_asn(d['prb_id'])
            if not src_asn:
                continue
            
            src_asn = int(asn)
            src_bgp_pfx = prb.probes_by_id[d['prb_id']]['prefix_v4']
            
            if src_bgp_pfx:
                src_bgp_pfx = src_bgp_pfx.replace('/', '_')

            if node_gran == 'bgp_pfx' and src_bgp_pfx == dst_bgp_pfx:
                continue
            if node_gran == 'asn' and src_asn == dst_asn:
                continue
            
            if remove_ixp_all and is_ixp(src_asn, src_bgp_pfx):
                print "This source is an IXP, skipping the trace", src_asn, src_bgp_pfx
                continue
            
            src_node_dict = {'asn': str(src_asn), 'bgp_pfx': src_bgp_pfx, 'pfx': None}
            
            iplinks = Result.get(d)
            nodelinks = parse_traceroute_v2(iplinks, src_asn, node_gran)
            if not nodelinks['_links']: continue
            
            nodes = nodelinks['_nodes']
            if '_ixps' in nodelinks:
                ixps_identified = nodelinks['_ixps']
                if remove_ixp_all:
                    nodelinks = remove_ixps(nodelinks)
            else:
                ixps_identified = []
                
            nodelinks = nodelinks['_links']
            if not nodelinks: continue
            
            # This check is good to have before we mess with the links
            # because if the trace is dis-continuous, it will be so
            # already.

            if not allow_discts_trace and not is_continuous(nodelinks):
                print "Trace is not continuous, skipping it"
                continue

            
            # These are attempts to avoid not having the origin node be the place
            # from where the measurement ran
            firstlink = nodelinks[0]
            if node_gran == 'bgp_pfx' and src_bgp_pfx and \
               firstlink['src']['bgp_pfx'] != src_bgp_pfx:
                nodelinks, nodes = add_node_to_nodelinks(nodelinks, nodes, src_node_dict)
            elif node_gran == 'asn' and src_asn and \
                 firstlink['src']['asn'] != src_asn:
                nodelinks, nodes = add_node_to_nodelinks(nodelinks, nodes, src_node_dict)

            reached_dst_asn, dst_asn_at, reached_dst_bgp_pfx, dst_bgp_pfx_at = \
                                            reached_dst(nodelinks, dst_asn, dst_bgp_pfx)

            if node_gran == 'bgp_pfx' and not reached_dst_bgp_pfx:
                # hanging trace on dest end
                pass
            elif node_gran == 'asn' and not reached_dst_asn:
                # hanging trace on dest end                
                pass
            elif node_gran == 'bgp_pfx' and len(dst_bgp_pfx_at) > 1:
                # reached destination multiple times, oh dear
                # logging.debug("dest_pfx_mult: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            elif node_gran == 'asn' and len(dst_asn_at) > 1:
                # reached destination multiple times, oh dear
                # logging.debug("dest_asn_mult: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            elif node_gran == 'bgp_pfx' and dst_bgp_pfx_at[0] < (len(nodelinks) - 1):
                print "Trace reached dest pfx earlier and continued going"
                # logging.debug("dest_pfx_early: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            elif node_gran == 'asn' and dst_asn_at[0] < (len(nodelinks) - 1):
                print "Trace reached dest asn earlier and continued going"
                # logging.debug("dest_asn_early: %s" % get_raw_trace_str(iplinks.ip_path))
                continue

            # If the traceroute did not reach the destination (at wtv granularity),
            # lets try to join it to the root of the DAG meaningfully
            if str(nodelinks[-1]['dst'][node_gran]) != str(dst_iden_attr):
                if node_gran =='asn' and are_siblings(str(nodelinks[-1]['dst']['asn']),
                                                      str(dst_iden_attr)):
                    print "Final hop was a sibling of the destination," + \
                        "replacing with dstasn", \
                        nodelinks[-1]['dst']['asn'], dst_asn
                    nodelinks[-1]['dst']['asn'] = str(dst_asn)

                elif node_gran == 'bgp_pfx' and nodelinks[-1]['dst']['asn'] == str(dst_asn):
                    # Traceroute reached the network, lets add a final link
                    # the prefix and bgp prefix granularity
                    final_link = {'src': nodelinks[-1]['dst'],
                                  'dst': {'pfx': dst_pfx, 'bgp_pfx': dst_bgp_pfx,
                                          'asn': dst_asn}, 'type': 'i'}
                    nodelinks.append(final_link)
                else:
                    # Dangling traces
                    link_that_killed_trace = nodelinks[-1]
                    ases_where_traces_go_to_die.add(link_that_killed_trace['dst']['asn'])
                    if not allow_discts_trace:
                        print "This trace will be dangling, so lets skip it", \
                            link_that_killed_trace['dst']['asn']
                        # logging.debug("dangling_trace: %s" % get_raw_trace_str(iplinks.ip_path))
                        continue
                
            if has_loop(nodelinks):
                print "Trace has loops, skipping it"
                # logging.debug("loopy_trace: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
    
            if nodelinks[-1]['src'][node_gran] == str(dst_iden_attr):
                # The final hop's src is the intended destination of the trace
                # but the trace kept going for some reason.
                # logging.debug("ongoing_final_hop: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
                                    
            str_path = []
            for link in nodelinks:
                str_path.append(link['src'][node_gran])
            str_path.append(link['dst'][node_gran])
            str_path = " ".join([str(x) for x in str_path])
            
            true_trace_count += 1
            prev_edge = None
            
            for link in nodelinks:
                v1 = create_new_node(G, link['src']['asn'], link['src']['bgp_pfx'],
                                     link['src']['pfx'], node_gran)
                v2 = create_new_node(G, link['dst']['asn'], link['dst']['bgp_pfx'],
                                     link['dst']['pfx'], node_gran)
                                    
                assert str(G.vp[node_gran][v1]) == str(link['src'][node_gran])
                assert str(G.vp[node_gran][v2]) == str(link['dst'][node_gran])
                
                ed = G.edge(v1,v2)
                if not ed:
                    ed = G.add_edge(v1, v2)
                    G.ep.origin[ed] = {0:{}, 1:{}, 2:{}, 3:{}, 4:{}, 5:{},
                                       6:{}, 7:{}, 8:{}, 9:{}, 10:{},
                                       11:{}, 12:{}, 13:{}, 14:{}, 15:{},
                                       16:{}, 17:{}, 18:{}, 19:{}, 20:{},
                                       21:{}, 22:{}, 23:{}}
                    
                if not prev_edge:                                
                    key = "gen"
                    G.vp.generated[v1] += 1
                    G.vp.str_path[v1] += "%s:%s;" % (d['endtime'], str_path)
                else:
                    key = prev_edge
                    
                if key in G.ep.origin[ed][trace_hour_count]:
                    G.ep.origin[ed][trace_hour_count][key] += 1
                else:
                    G.ep.origin[ed][trace_hour_count][key] = 1
                    
                if link['type'] == 'i':
                    G.ep.type[ed] = 1
                else:
                    G.ep.type[ed] = 0

                if not G.ep.start_ts[ed]:
                    G.ep.start_ts[ed] = d['endtime']
                elif int(d['endtime']) < G.ep.start_ts[ed]:
                    G.ep.start_ts[ed] = d['endtime']
                
                if not G.ep.last_ts[ed]:
                    G.ep.last_ts[ed] = d['endtime']
                elif int(d['endtime']) > G.ep.last_ts[ed]:
                     G.ep.last_ts[ed] = d['endtime']
                     
                prev_edge = "%s-%s" % (link['src'][node_gran], link['dst'][node_gran])
                if not root_node.out_degree() == 0:
                    print "Root node now has an outgoing edge"
                    reached_dst_asn, dst_asn_at, reached_dst_bgp_pfx, dst_bgp_pfx_at =\
                       reached_dst(nodelinks, dst_asn, dst_bgp_pfx)
                    print link
            dag_dict[dst_iden_attr] = G
            # print "Parsed trace to: %s, the DAG has %d edges" % (dst_iden_attr, G.num_vertices())

    print "Parsed %d total traces of which %d have meaningful information" %\
        (total_trace_count, true_trace_count)
    return dag_dict, total_trace_count, true_trace_count

def get_path_prob(gr, path):
    transition_prob = []
    incident_on_node = {}
    for x, y in zip(path, path[1:]):
        edge = gr.edge(x,y)
        source = edge.source()
        target = edge.target()
        if gr.vp.mmt_type[source] == 'SH':
            assert not gr.ep.origin[edge]
            assert source.out_degree() == 1
            transition_prob.append(1.0)
            continue
            
        origin_through_edge = gr.ep.origin[edge]
        if source in incident_on_node:
            incident_on_src = incident_on_node[source]
        else:
            incident_on_src = 0
            for in_nbr in source.in_neighbors():
                if in_nbr == source: continue
                incident_edge = gr.edge(in_nbr, source)
                assert incident_edge
                incident_origin = gr.ep.origin[incident_edge]
                if not incident_origin:
                    assert gr.vp.mmt_type[in_nbr] == 'SH'
                    incident_origin = []
                for origin in incident_origin:
                    incident_on_src += gr.ep.origin[incident_edge][origin]
            incident_on_src += gr.vp.generated[source]
            incident_on_node[source] = incident_on_src
        traversed_on_edge = 0
        for org in origin_through_edge:
            traversed_on_edge += origin_through_edge[org]
        # Laplacian smoothing
        prob = float(traversed_on_edge + 1)/(incident_on_src + source.out_degree())
        assert prob > 0
        assert prob <= 1
        transition_prob.append(prob)
    return round(reduce(mul, transition_prob, 1), 4)

def yens_algorithm(gr, src_node, dst_node):
    # Heavily inspired from Networkx's implementation
    # of Yen's algorithm (shortest_simple_paths)

    # this is safe since we do not split dst nodes in DAGs
    dst_node_asn = node_to_asn(gr, dst_node)
    listA = list()
    listB = PathBuffer()
    prev_path = None
    while True:
        if not prev_path:
            vlist, elist = shortest_path(gr, src_node, dst_node, weights=gr.ep.weight)
            if vlist:
                weight = get_path_weight(gr, vlist)
                listB.push(weight, vlist)
        else:
            ignore_nodes = set()
            ignore_edges = set()
            for i in range(1, len(prev_path)):
                root = prev_path[:i]
                root_weight = get_path_weight(gr, root)
                for path in listA:
                    if path[:i] == root:
                        ignore_edges.add(gr.edge(path[i-1], path[i]))
                        
                ignore_nodes.add(root[-1])
                gr_view = get_graph_view(gr, ignore_edges, [])
                spur_vlist, spur_elist = shortest_path(gr_view,
                                                       gr_view.vertex(int(root[-1])),
                                                       gr_view.vertex(int(dst_node)),
                                                       weights=gr_view.ep.weight)
                if spur_vlist:
                    try:
                        spur_weight = get_path_weight(gr_view, spur_vlist)
                    except:
                        print "MAD MAD YEN"
                        pdb.set_trace()
                    complete_path = root[:-1] + [gr.vertex(int(x)) for x in spur_vlist]
                    listB.push(root_weight + spur_weight, complete_path)

        if listB:
            path = listB.pop()
            yield path
            listA.append(path)
            prev_path = path
        else:
            break

def dfs_paths(gr, src_node, dst_node):
    visited = set()
    stack = [tuple([src_node, src_node])]
    while stack:
        path_tuple = stack.pop()
        vertex = path_tuple[-1]
        path = list(path_tuple[:-1])
        visited.add(tuple(path))
        for next in set(vertex.out_neighbours()):
            if tuple(path + [next]) in visited:
                continue
            if next == dst_node:
                yield path + [next]
            else:
                stack.append(tuple( path + [next] + [next]))

def get_ranked_paths(gr, src_nodes, dst_node):
    assert src_nodes, "No source nodes passed"
    if dst_node.in_degree() == 0:
        assert False, "destination node is disconnected, WTF " +  gr.vp.bgp_pfx[dst_node]

    src_dst_paths = []
    for src_node in src_nodes:
        src_dst_paths_gen = yens_algorithm(gr, src_node, dst_node)
        count = 0
        for path in src_dst_paths_gen:
            count += 1
            if count > PER_SRC_DST_CUTOFF: break
            prob = get_path_prob_fast(gr, path)
            src_dst_paths.append((path, prob))
            
    src_dst_paths = sorted(src_dst_paths, key=lambda x: x[1], reverse=True)
    src_dst_paths = src_dst_paths[:MAX_PATHS]
    if not src_dst_paths: return []
    
    src_dst_paths_hops = []
    total_prob = sum([x[1] for x in src_dst_paths])
    assert total_prob <= 1.1
    assert total_prob >= 0
    if total_prob == 0: pdb.set_trace()
    for path, prob in src_dst_paths:
        try:
            hop_path = [gr.vp.bgp_pfx[x] for x in path]
        except:
            pdb.set_trace()
        new_prob = prob/float(total_prob)
        src_dst_paths_hops.append((hop_path, new_prob))
        
    return src_dst_paths_hops

def can_split_node(gr, node):
    out_neighbors = node.out_neighbours()
    out_edges = set()
    for out_nbr in out_neighbors:
        out_edge = gr.edge(node, out_nbr)
        out_edges.add(out_edge)

    edges_carrying_generated_traces = set()
    origin_dict = {}
    for out_edge in out_edges:
        origin = gr.ep.origin[out_edge]
        origin_dict[out_edge] = set(origin.keys())
        if "gen" in origin:
            assert origin["gen"]
            edges_carrying_generated_traces.add(out_edge)
            origin_dict[out_edge].remove("gen")
        
    if len(edges_carrying_generated_traces) > 1:
        return False
    
    for origin_set_key_1 in origin_dict:
        for origin_set_key_2 in origin_dict:
            if origin_set_key_1 == origin_set_key_2: continue
            origin_set_1 = origin_dict[origin_set_key_1]
            origin_set_2 = origin_dict[origin_set_key_2]            
            if not origin_set_1.isdisjoint(origin_set_2):
                return False
    return True

def is_splittable_graph(gr):
    nodes = [x for x in gr.vertices()]
    nodes_violating_dest_based_routing = set()
    for node in nodes:
        if node.out_degree() <= 1: pass
        else:
            nodes_violating_dest_based_routing.add(node)
    nodes_violating_dest_based_routing = set(nodes_violating_dest_based_routing)
    assert len(nodes_violating_dest_based_routing) >= 1
    can_split = True
    for node in nodes_violating_dest_based_routing:
        if not can_split_node(gr, node):
            print "%s is not splittable" % gr.vp.asn[node] 
            can_split = False
            break
    if can_split:
        return True
    else:
        return False
    
def split_to_tree(gr, fname, save_to_disk=True):
    gr_copy = Graph(gr) # deep copy the graph
    # new property that keep track of dummy nodes
    vprop_dup = gr_copy.new_vertex_property("int", val=0)
    gr_copy.vp.duplicate = vprop_dup
    nodes = [x for x in gr.vertices()]
    for node in nodes:
        if node.out_degree() == 1: continue
        if node.out_degree() == 0 and gr.vp.prefix[node]: continue
        assert node.out_degree() > 1
        assert can_split_node(gr, node)
        # this should split the node and modify the necessary edges
        node_in_copy = asn_to_node(gr_copy, gr.vp.asn[node])
        assert gr_copy.vp.duplicate[node_in_copy] == 0 # It cannot be split already
        gr_copy = split_node(gr_copy, node_in_copy)
    if save_to_disk:
        fname_new = fname.split('.gt')[0] + ".split" + ".gt"
        print "writing to:", fname_new
        gr_copy.save(fname_new)
    return gr_copy

def get_edge_prob(gr, edge, epsilon=0.001):
    # Each graph that this gets has been split based based on
    # prior hop routing. If there still exist cases of
    # probabilistic routing, this method has the right way
    # of evaluating them.
    prob = 0.0
    source = edge.source()
    target = edge.target()
    incident_on_src = 0
    traversed_on_edge = 0

    if source.out_degree() == 1:
        return 1.0, 1.0
    
    for in_nbr in source.in_neighbors():
        if in_nbr == source: assert False, "Self loop"
        incident_edge = gr.edge(in_nbr, source)
        incident_on_src += sum(gr.ep.super_origin[incident_edge].values())
        
    for entering_edge_pfx in gr.ep.super_origin[edge]:
        if entering_edge_pfx == 'gen': continue
        if find_vertex(gr, gr.vp.bgp_pfx, entering_edge_pfx):
            entering_edge = gr.edge(
                find_vertex(gr, gr.vp.bgp_pfx, entering_edge_pfx)[0], source)
            if entering_edge:
                traversed_on_edge += gr.ep.super_origin[edge][entering_edge_pfx]

    if incident_on_src == 0:
        assert source.in_degree() == 0
        prob = -1
    else:
        prob = float(traversed_on_edge)/incident_on_src
        if prob == 0 :
            prob = epsilon
        assert prob > 0
        assert prob <= 1.15 # round off errors

    # Generated trace probability
    prob_gen = -1
    if 'gen' in gr.ep.super_origin[edge]:
        gen_on_edge = gr.ep.super_origin[edge]['gen']
        all_gen_by_source = 0
        for out_nbr in source.out_neighbors():
            out_edge = gr.edge(source, out_nbr)
            if 'gen' in gr.ep.super_origin[out_edge]:
                all_gen_by_source += gr.ep.super_origin[out_edge]['gen']
        assert all_gen_by_source >= gen_on_edge
        prob_gen = float(gen_on_edge)/all_gen_by_source

    if prob_gen == -1 and prob != -1:
        assert prob > 0.0
        assert prob < 1.15
        prob_gen = prob
    if prob == -1 and prob_gen != -1:
        assert prob_gen <= 1.1
        assert prob_gen >= 0
        prob = prob_gen

    assert prob > 0.0
    assert prob_gen > 0.0
    assert prob <= 1.15
    assert prob_gen <= 1.15
    return min(1, prob), min(1, prob_gen)

def assign_edge_weights(gr, order=1, epsilon=0.001):
    # edge weight = - log(edge_probability) + epsilon
    # for now using epsilon as a way of adding really
    # small weights on all edges, even those with prob = 1
    weight_prop = gr.new_edge_property("float")
    gr.ep.weight = weight_prop
    gen_weight_prop = gr.new_edge_property("float")
    gr.ep.gen_weight = gen_weight_prop
    prob_prop = gr.new_edge_property("float")
    gr.ep.prob = prob_prop
    gen_prob_prop = gr.new_edge_property("float")
    gr.ep.gen_prob = gen_prob_prop
    
    for edge in gr.edges():
        prob, gen_prob = get_edge_prob(gr, edge)
        gr.ep.prob[edge] = prob
        gr.ep.gen_prob[edge] = gen_prob
        try:
            gr.ep.weight[edge] = - math.log(gr.ep.prob[edge])
            gr.ep.gen_weight[edge] = - math.log(gr.ep.gen_prob[edge])
        except:
            pdb.set_trace()
    return gr

def node_to_asn(gr, node):
    if 'duplicate' in gr.vp and gr.vp.duplicate[node] > 0:
        asn = "%d-%d" % (gr.vp.asn[node], gr.vp.duplicate[node])
    else:
        asn = str(gr.vp.asn[node])
    return asn

def pathify(gr, asn_path):
    path = []
    for asn in asn_path:
        node = asn_to_node(gr, asn)
        path.append(node)
    return path

def asn_to_node(gr, asn):
    if '-' not in asn:
        node = find_vertex(gr, gr.vp.asn, asn)
        assert len(node) == 1
        node = node[0]
    else:
        asn_, dup_num = asn.split('-')
        asn_ = asn_.strip()
        dup_num = dup_num.strip()
        nodes = find_vertex(gr, gr.vp.asn, asn_)
        node = None
        for node_ in nodes:
            if gr.vp.duplicate[node_] == int(dup_num):
                assert not node
                node = node_
    return node

def get_graph_view(gr, ignore_edges, ignore_nodes):
    u = GraphView(gr, vfilt=lambda v: v not in ignore_nodes,
                  efilt=lambda e: e not in ignore_edges)
    return u

def asn_pathify(gr, path):
    asn_path = []
    for node in path:
        asn = gr.vp.asn[node]
        match_vertices = find_vertex(gr, gr.vp.asn, asn)
        if len(match_vertices) == 1:
            asn_path.append(str(asn))
        else:
            dup_num = gr.vp.duplicate[node]
            assert dup_num > 0
            asn_path.append("%d-%d" % (asn, dup_num))
    return asn_path

def get_path_weight(gr, path):
    # path is a list of vertices (not edges!)
    if len(path) == 1: return 0.0
    weight = gr.ep.gen_weight[gr.edge(path[0], path[1])]
    for x, y in zip(path[1:], path[2:]):
        edge = gr.edge(x,y)
        weight += gr.ep.weight[edge]
    return weight

def get_path_prob_fast(gr, vlist):
    probs = [gr.ep.gen_prob[gr.edge(vlist[0], vlist[1])]]
    for x, y in zip(vlist[1:], vlist[2:]):
        edge = gr.edge(x,y)
        prob = gr.ep.prob[edge]
        probs.append(prob)
    prob = reduce(mul, probs, 1)
    return prob

@timeout_decorator.timeout(100)
def predict_pc_path(src_asn, dst_prefix):
    grfname = os.path.join(GRAPHS_DIR, "%s.gt" % dst_prefix)
    if os.path.isfile(grfname):
        gr = load_graph(grfname, fmt="gt")
    else:
        return []
    print "Dst Prefix: %s with %d nodes and %d edges" % \
        (dst_prefix, gr.num_vertices(), gr.num_edges())
    if not is_DAG(gr):
        print "Not DAG", dst_prefix
        if is_splittable_graph(gr):
            print "Splitting it", dst_prefix
            gr_modified = split_to_tree(gr, grfname, save_to_disk=True)
            gr = gr_modified
        # else:
        #    print "Not DAG, can't split, move on", dst_prefix
        #    return []
    gr = assign_edge_weights(gr)
    dst_node = find_vertex(gr, gr.vp.prefix, dst_prefix)
    assert len(dst_node) == 1
    dst_node = dst_node[0]
    src_nodes = find_vertex(gr, gr.vp.asn, int(src_asn))
    paths = get_ranked_paths(gr, src_nodes, dst_node)
    return paths

@memoized
def build_rtree_with_pathcache_graphs(dirname):
    fnames = glob.glob(dirname + "*.gt")
    rtree_gr_prefs = radix.Radix()
    for fname in fnames:
        identifier = fname.split('/')[-1].split('.gt')[0]
        ip = identifier.split('_')[0]
        preflen = identifier.split('_')[1]
        rnode = rtree_gr_prefs.add(network=ip, masklen=int(preflen))
        rnode.data["fname"] = fname
    return rtree_gr_prefs

def get_graph(identifier, dst, dirname):
    gr = None
    fnames = glob.glob(dirname + "/*.gt")
    if dirname + '/%s.gt' % identifier in fnames:
        gr = load_graph(dirname + '/%s.gt' % identifier)
        dst_prefix = identifier
    else:
        fname_rtree = build_rtree_with_pathcache_graphs(dirname)
        rnode = fname_rtree.search_best(dst)
        if not rnode:
            print "Do not have a dest graph for IP", identifier
            return None, None
        grfname = rnode.data["fname"]
        dst_prefix = grfname.split('/')[-1].split('.gt')[0]
        gr = load_graph(grfname)
    return gr, dst_prefix

def predict_pc_path_ip(src, dst, dirname, dst_type= 'ip', src_type="ip", order=1):
    assert src_type in ["asn", "ip", "bgp_pfx"]
    if dst_type == 'ip':
        dst_prefix = ip2pref_bgp_ts(dst)
    elif dst_type == 'bgp_pfx':
        assert '_' in dst
        dst_prefix = dst
    else:
        assert dst_type == 'asn'
        # DO NOT KNOW WHAT TO DO, COME BACK HERE.
        
    if order == 1:
        gr, dst_prefix = get_graph(dst_prefix, dst, dirname)
        if not gr: return []
        
        print "Dst Prefix: %s with %d nodes and %d edges" % \
            (dst_prefix, gr.num_vertices(), gr.num_edges())
    
        dst_node = find_vertex(gr, gr.vp.bgp_pfx, dst_prefix)
        assert len(dst_node) == 1
        dst_node = dst_node[0]

        # Exact match for source node
        if src_type == 'ip':
            src_prefix = ip2pref_bgp_ts(src)
            src_nodes = find_vertex(gr, gr.vp.bgp_pfx, src_prefix)
        elif src_type == 'bgp_pfx':
            src_nodes = find_vertex(gr, gr.vp.bgp_pfx, src)
        elif src_type == 'asn':
            src_nodes = find_vertex(gr, gr.vp.asn, int(src))

        if not src_nodes:
            print "Source not in graph", src
            return []
        gr = assign_edge_weights(gr, order=1)
        
    #try:
    paths = get_ranked_paths(gr, src_nodes, dst_node)
    print paths
    #except:
    #    paths = []
    return paths

def parse_mmt_metadata_ripe(fname, mmt_type='traceroute'):
    mmt_id_dict = {}
    with open(fname) as fi:
        for row in fi:
            mdata_row = json.loads(row)
            if mdata_row['type']['name'] != mmt_type: continue
            msm_id = mdata_row['msm_id']
            mmt_id_dict[msm_id] = {'af': mdata_row['af'], 'is_oneoff': mdata_row['is_oneoff'],
                                   'probes_requested': mdata_row['participant_count'],
                                   'dst_addr': mdata_row['dst_addr'],
                                   'dst_name': mdata_row['dst_name'],
                                   'start_time': mdata_row['start_time'],
                                   'stop_time': mdata_row['stop_time'],
                                   'resolve_on_probe': mdata_row['resolve_on_probe']}
    return mmt_id_dict

def send_traceroute_write_job(mmt_id, start=None, end=None, beanstalkport=14711):
    if start and end:
        is_success, results = AtlasResultsRequest(msm_id=mmt_id, start=start, end=end).create()
    else:
        is_success, results = AtlasResultsRequest(msm_id=mmt_id).create()
    if is_success:
        print mmt_id, start, end
        beanstalk = beanstalkc.Connection(host='localhost', port=beanstalkport)
        for result in results:
            if not 'result' in result: continue
            trace = []
            dst_addr = result['dst_addr']
            end_ts = result['endtime']
            probe_id = result['prb_id']
            src_addr = result['src_addr']
            for hop in result['result']:
                if 'result' not in hop: continue
                hop_nr = hop['hop']
                hrs = set()
                for hr in hop['result']:
                    if 'from' in hr:
                        hrs.add(hr['from'])
                if not hrs:
                    hop_val = None
                else:
                    hop_val = list(hrs)[0]
                trace.append(hop_val)
            trace_hops = ';'.join([str(x) for x in trace])
            beanstalk.put(str("%s, %s, %d, %d, %d, %s" % (dst_addr, src_addr, end_ts, int(mmt_id),
                                                  int(probe_id), trace_hops)))
        beanstalk.close()

# def init_log(identifier):
#     import logging
#     logging.basicConfig(filename='logs/%s.log' % identifier,
#                         format="%(asctime)s %(message)s",
#                         level=logging.ERROR)    

'''This method lets you construct a DAG for an IP address at
either ASN or BGP prefix granularity. You can pass it MSMs of your choice
and/or let it search for the measurements.'''
def compute_dest_based_graphs_offline(fname,
                              dag_dict={}, node_gran='bgp_pfx', ts=None,
                              allow_discts_trace=True, remove_ixp_all=False):
    '''
    1. root_node_gran an take 4 values: 'pfx', 'bgp_pfx', 'bgp_atom', 'asn'
    Similarly, inter_node_gran can the same 4 value.
    3. dag_dict: Dictionary consisting of identifier (pfx or asn) to DAG objects.
    This allows incrementally adding to the DAGs in successive calls to this function.
    '''
    if ts == 0:
        ts = None        
    print "In compute dest based graphs offline", fname, node_gran
    identifier = fname.split('traceroute-')[-1].split('.bz2')[0]
    timestamp = dateutil.parser.parse(identifier)
    timestamp_int = int(calendar.timegm(timestamp.timetuple()))
    import logging
    # logging.basicConfig(filename='logs/%s.log' % identifier,
    #                     format="%(funcName)s: %(lineno)d: %(message)s")

    directory =  HIST_DATA % (node_gran, identifier)
    if not os.path.exists(directory):
        os.makedirs(directory)

    #if len(os.listdir(directory)) > 100:
    #    print "Already existing DAGs in", directory
    #    return
    
    total_trace_count = 0
    true_trace_count = 0
    with bz2.BZ2File(fname) as fi:
        for line in fi:
            d = json.loads(line)
            trace_endtime =  int(d['endtime'])
            # trace_hour_count = datetime.datetime.fromtimestamp(trace_endtime).hour
            
            # Error in any hop of the trace, skip
            error = [x for x in d['result'] if 'error' in x]
            if error:
                continue
            try:
                measurement_target = d['dst_addr']
            except KeyError:
                continue
            
            dst_pfx, dst_bgp_pfx, dst_asn = get_pref_asn(measurement_target, ts)
            if not dst_bgp_pfx or not dst_asn: continue
            
            if is_ixp(dst_asn, dst_bgp_pfx):
                if remove_ixp_all:
                    # logging.error("dst_is_ixp: rempve_ixp_all flag is on, bailing %s %s" %
                    #               (dst_asn, dst_bgp_pfx))
                    continue
            # dst_iden_attr is the identifying characteristic
            # of the destination: it is either the destination BGP prefix, destination ASN
            # or destination /24.
            dst_iden_attr = get_iden_attr(dst_asn, dst_bgp_pfx, dst_pfx, node_gran)
            if dst_iden_attr not in dag_dict:
                G = init_graph()
                G.gp.granularity = node_gran
            else:
                G = dag_dict[dst_iden_attr]
                
            root_node = create_new_node(G, dst_asn, dst_bgp_pfx, dst_pfx, node_gran)
            
            total_trace_count += 1
            
            src_asn = prb.get_probe_asn(d['prb_id'])
            if not src_asn:
                continue
            
            src_asn = int(asn)
            src_bgp_pfx = prb.probes_by_id[d['prb_id']]['prefix_v4']
            src_pfx = '.'.join(d['src_addr'].split('.')[:-1] + ['0'])
            
            if src_bgp_pfx:
                src_bgp_pfx = src_bgp_pfx.replace('/', '_')

            if node_gran == 'bgp_pfx' and src_bgp_pfx == dst_bgp_pfx:
                continue
            if node_gran == 'asn' and src_asn == dst_asn:
                continue
            
            if remove_ixp_all and is_ixp(src_asn, src_bgp_pfx):
                # logging.error("src_is_ixp: rempve_ixp_all flag is on, bailing %s %s" %
                #                   (src_asn, src_bgp_pfx))
                continue
            
            
            src_node_dict = {'asn': str(src_asn), 'bgp_pfx': src_bgp_pfx, 'pfx': src_pfx}
            
            iplinks = Result.get(d)
            nodelinks = parse_traceroute_v2(iplinks, node_gran)
            if not nodelinks['_links']: continue
            
            nodes = nodelinks['_nodes']
            if '_ixps' in nodelinks:
                ixps_identified = nodelinks['_ixps']
                if remove_ixp_all:
                    nodelinks = remove_ixps(nodelinks)
            else:
                ixps_identified = []
                
            nodelinks = nodelinks['_links']
            if not nodelinks: continue
            
            # This check is good to have before we mess with the links
            # because if the trace is dis-continuous, it will be so
            # already.
            if not allow_discts_trace and not is_continuous(nodelinks):
                #print "Trace is not continuous, skipping it"
                # logging.error("dicts_trace: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            
            # These are attempts to avoid not having the origin node be the place
            # from where the measurement ran
            firstlink = nodelinks[0]
            if node_gran == 'bgp_pfx' and src_bgp_pfx and \
               firstlink['src']['bgp_pfx'] != src_bgp_pfx:
                nodelinks, nodes = add_node_to_nodelinks(nodelinks, nodes, src_node_dict)
            elif node_gran == 'asn' and src_asn and \
                 firstlink['src']['asn'] != src_asn:
                nodelinks, nodes = add_node_to_nodelinks(nodelinks, nodes, src_node_dict)

            reached_dst_asn, dst_asn_at, reached_dst_bgp_pfx, dst_bgp_pfx_at = \
                                            reached_dst(nodelinks, dst_asn, dst_bgp_pfx)

            if node_gran == 'bgp_pfx' and not reached_dst_bgp_pfx:
                # hanging trace on dest end
                pass
            elif node_gran == 'asn' and not reached_dst_asn:
                # hanging trace on dest end                
                pass
            elif node_gran == 'bgp_pfx' and len(dst_bgp_pfx_at) > 1:
                # reached destination multiple times, oh dear
                #logging.error("dest_pfx_mult: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            elif node_gran == 'asn' and len(dst_asn_at) > 1:
                # reached destination multiple times, oh dear
                #logging.error("dest_asn_mult: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            elif node_gran == 'bgp_pfx' and dst_bgp_pfx_at[0] < (len(nodelinks) - 1):
                # print "Trace reached dest pfx earlier and continued going"
                #logging.error("dest_pfx_early: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            elif node_gran == 'asn' and dst_asn_at[0] < (len(nodelinks) - 1):
                # print "Trace reached dest asn earlier and continued going"
                #logging.error("dest_asn_early: %s" % get_raw_trace_str(iplinks.ip_path))
                continue

            # If the traceroute did not reach the destination (at wtv granularity),
            # lets try to join it to the root of the DAG meaningfully
            if str(nodelinks[-1]['dst'][node_gran]) != str(dst_iden_attr):
                if node_gran =='asn' and are_siblings(str(nodelinks[-1]['dst']['asn']),
                                                      str(dst_iden_attr)):
                    #logging.error("dst_asn_sibling: %s %s" \
                    #              % (str(nodelinks[-1]['dst']['asn']), str(dst_asn)))
                    nodelinks[-1]['dst']['asn'] = str(dst_asn)

                elif node_gran == 'bgp_pfx' and nodelinks[-1]['dst']['asn'] == str(dst_asn):
                    # Traceroute reached the network, lets add a final link
                    # the prefix and bgp prefix granularity
                    final_link = {'src': nodelinks[-1]['dst'],
                                  'dst': {'pfx': dst_pfx, 'bgp_pfx': dst_bgp_pfx,
                                          'asn': dst_asn}, 'type': 'i'}
                    nodelinks.append(final_link)
                else:
                    # Dangling traces
                    link_that_killed_trace = nodelinks[-1]
                    ases_where_traces_go_to_die.add(link_that_killed_trace['dst']['asn'])
                    if not allow_discts_trace:
                        # print "This trace will be dangling, so lets skip it", \
                        #    link_that_killed_trace['dst']['asn']
                        # logging.error("dangling_trace: %s" % get_raw_trace_str(iplinks.ip_path))
                        continue
                
            if has_cycles(nodelinks, node_gran):
                # logging.error("loopy_trace: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
            
            # I think this check is redundant
            if nodelinks[-1]['src'][node_gran] == str(dst_iden_attr):
                # The final hop's src is the intended destination of the trace
                # but the trace kept going for some reason.
                # logging.error("ongoing_final_hop: %s" % get_raw_trace_str(iplinks.ip_path))
                continue
                                    
            str_path = []
            for link in nodelinks:
                str_path.append(link['src'][node_gran])
            str_path.append(link['dst'][node_gran])
            str_path = " ".join([str(x) for x in str_path])
            
            true_trace_count += 1
            previous_src = None
            previous_dst = None
            for link in nodelinks:
                v1 = create_new_node(G, link['src']['asn'], link['src']['bgp_pfx'],
                                     link['src']['pfx'], node_gran)
                v2 = create_new_node(G, link['dst']['asn'], link['dst']['bgp_pfx'],
                                     link['dst']['pfx'], node_gran)
                                    
                assert str(G.vp[node_gran][v1]) == str(link['src'][node_gran])
                assert str(G.vp[node_gran][v2]) == str(link['dst'][node_gran])
                
                if link['src'] in ixps_identified:
                    G.vp.ixp[v1] = True
                if link['dst'] in ixps_identified:
                    G.vp.ixp[v2] = True
                    
                ed = G.edge(v1,v2)
                if not ed:
                    ed = G.add_edge(v1, v2)
                    G.ep.origin[ed] = {timestamp_int:{}}

                if not previous_src:
                    key = "gen"
                    G.vp.generated[v1] += 1
                    G.vp.str_path[v1] += "%s:%s;" % (trace_endtime, str_path)
                elif previous_dst == link['src'][node_gran]:
                    key = previous_src
                    prev_hop_vertex = find_vertex(G, G.vp[node_gran], previous_src)
                    assert len(prev_hop_vertex) == 1
                    prev_hop_vertex = prev_hop_vertex[0]
                    assert G.edge(prev_hop_vertex, v1), "Edge should exist here."
                else:
                    key = 'unknown'

                if key in G.ep.origin[ed][timestamp_int]:
                    G.ep.origin[ed][timestamp_int][key] += 1
                else:
                    G.ep.origin[ed][timestamp_int][key] = 1
                    
                if link['type'] == 'i':
                    G.ep.type[ed] = 1
                else:
                    G.ep.type[ed] = 0

                if not G.ep.start_ts[ed]:
                    G.ep.start_ts[ed] = trace_endtime
                elif trace_endtime < G.ep.start_ts[ed]:
                    G.ep.start_ts[ed] = trace_endtime
                
                if not G.ep.last_ts[ed]:
                    G.ep.last_ts[ed] = trace_endtime
                elif trace_endtime > G.ep.last_ts[ed]:
                     G.ep.last_ts[ed] = trace_endtime
                     
                previous_src = link['src'][node_gran]
                previous_dst = link['dst'][node_gran]
                
                if not root_node.out_degree() == 0:
                    print "Root node now has an outgoing edge"
                    reached_dst_asn, dst_asn_at, reached_dst_bgp_pfx, dst_bgp_pfx_at =\
                       reached_dst(nodelinks, dst_asn, dst_bgp_pfx)
                    print link
                    assert False
            dag_dict[dst_iden_attr] = G
            # print "Parsed trace to: %s, the DAG has %d edges" % (dst_iden_attr, G.num_vertices())

    print "Parsed %d total traces of which %d have meaningful information" %\
        (total_trace_count, true_trace_count)
    
    for dst_iden_attr in dag_dict:
        gr = dag_dict[dst_iden_attr]
        gr.save(directory + "%s.gt" % dst_iden_attr)
        
    print "Written all to directory", directory
