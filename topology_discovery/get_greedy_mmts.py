#!/usr/bin/python
# standard libraries
import json, csv
import random
import os, sys
import copy
import pdb
from multiprocessing import Pool

# non-standard libraries
from graph_tool.topology import is_DAG, shortest_path

# local files
project_home = os.path.join(os.path.realpath(__file__), os.pardir)
project_home = os.path.abspath(os.path.join(project_home, os.pardir))
sys.path.append(project_home)
sys.path.append(os.path.join(project_home, 'tools'))
sys.path.append(os.path.join(project_home, 'topology_discovery'))
import internet_tools, get_ripe_measurement, args_dicts
from DAG import *
import mkit.inference.ip_to_asn as ip2asn
from mkit.ripeatlas import probes
import settings

# command line argument management
parser = get_ripe_measurement.parser
parser.description = 'Create and serialize DAGs from RIPE atlas measurments'
silent = get_ripe_measurement.silent
NOSH = internet_tools.NOSH

parser.add_argument('strategy', choices=['iterative', 'batch', 'geod', 'random'], default='iterative', nargs='?',
                    help='Defines the method used to choose measurements.\n' \
                         ' * "iterative" greedily chooses a measurement, incorporates it into the model, then iterates. ' \
                         'This is the slowest choice and gives the most coverage.\n'\
                         ' * "batch" greedily chooses all measurements from the model, then runs them. A faster ' \
                         'alternative to "iterative".\n' \
                         ' * "geod" chooses measurements in a geo-distributed way based on the model.\n' \
                         ' * "random" chooses measurements randomly. Useful only for evaluation.\n' \
                         'The default is "iterative".')
parser.add_argument('--source', choices=['ripe'], default='ripe', metavar='<data source>',
                    help='The source from which to make measurements')
parser.add_argument('--processes', **args_dicts.processes_args)
parser.add_argument('--maxtasksperchild', **args_dicts.maxtasksperchild_args)
#parser.add_argument('--batch', action='store_true', help='If included, will use a faster but lower-coverage choice of measurements')
parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')

args = parser.parse_known_args()[0]

source = args.source
#batch = args.batch
strategy = args.strategy

if NOSH:
    save_dir = settings.GRAPH_DIR_FINAL_PREF
    NOSH_str = '-nosh'
else:
    save_dir = settings.GRAPH_DIR_FINAL_PREF_SH
    NOSH_str = ''
if not os.path.exists(save_dir):
    os.makedirs(save_dir)

all_probes = probes.all_probes

if source == 'ripe':
    print "Getting source probes from RIPE"
    type_probes = 'ripe'
    probes_per_asn = {}
    for pr in all_probes:
        if 'system-ipv4-works' in pr['tags'] and pr['status_name'] == 'Connected':
            asn = pr['asn_v4']
        if not asn: continue
        if asn in probes_per_asn:
            probes_per_asn[asn].append(pr['id'])
        else:
            probes_per_asn[asn] = [pr['id']]
            
if source == 'pl':
    print "Getting source probes from PL"
    type_probes = 'pl'
    with open("pl_probe_asns.json") as fi:
        probes_per_asn = json.load(fi)

if source == 'ark':
    print "Getting source probes form CAIDA Ark"
    type_probes = 'ark'
    with open("ark_probe_asns.json") as fi:
        probes_per_asn = json.load(fi)

# acts as a dictionary of graphs, but doesn't load them into memory until and unless needed
class lazy_DAG_loader(object):
    def __init__(self):
        self.d = {}
        self.missing = set()

    @staticmethod
    def _sanitize_key(key):
        try:
            return int(key)
        except ValueError:
            return int(internet_tools.ip2asn_bgp(key))

    def __contains__(self, key):
        key = lazy_DAG_loader._sanitize_key(key)
        if key in self.missing:
            return False
        if key in self.d:
            return True
        fname = os.path.join(save_dir, str(key) + '.gt')
        if os.path.isfile(fname):
            self.d[key] = load_DAG(fname)
            return True
        self.missing.add(key)
        return False

    def __getitem__(self, key):
        input_key = key
        if type(key) == type(slice(1)):
            keys = range(*key.indices(397213))
            slice_key = True
        else:
            keys = [lazy_DAG_loader._sanitize_key(key)]
            slice_key = False
        ret = {}
        for key in keys:
            if key in self:
                ret[key] = self.d[key]
        if not slice_key:
            if len(ret) == 0:
                raise KeyError(str(input_key))
            return ret[keys[0]]
        if len(ret) == 0:
            raise KeyError(str(input_key))
        return ret

    def __delitem__(self, key):
        del self.d[key]

asn_graphs = lazy_DAG_loader()

data_dir = os.path.join(project_home, 'topology_discovery', 'data')
top_content_prefs = []
with open(os.path.join(data_dir, "per_prefix_count.csv")) as fi:
    reader = csv.reader(fi)
    for row in reader:
        if row[0] == 'pref': continue
        if int(row[1]) < 72: break
        top_content_prefs.append(row[0])

with open(os.path.join(data_dir, "random_ips.json")) as fi:
    random_prefs = json.load(fi)

with open(os.path.join(data_dir, "top_cust_cone_ips.json")) as fi:
    top_cust_cone_prefs = json.load(fi)

with open(os.path.join(data_dir, "top_eyeball_prefs.json")) as fi:
    top_eyeball_prefs = json.load(fi)

# gets the next best probe to use: not efficient for anything except iterative
# graph is the prefix graph
# probes is an iterable of ASNs for which there are probes
# covered is the set of ASes that have already been covered
def get_next_best(graph, probes, covered=set()):
    best_utility = 0
    best_probe = None
    target = graph.v_by_ASN(graph.gp.root)
    graph.filter_unlikely_edges()
    for probe in probes:
        gain = internet_tools.get_single_homed_customers(probe)
        probe_vertex = graph.v_by_ASN(probe)
        sp = set(graph.vp.ASN[v] for v in shortest_path(graph, probe_vertex, target)[0])
        utility = set(gain).union(sp)
        new_utility = len(utility - covered)
        if new_utility > best_utility:
            best_utility = new_utility
            best_probe = probe

    return best_probe

def geo_distributed_coverage(subsets, k, superset):
    print "Geodistributed selection"
    superset_paths = copy.deepcopy(superset)
    subsets_copy = copy.deepcopy(subsets)
    nodes_covered = []
    mmts_ordered = []
    countries_covered = []
    measurements = subsets.keys()
    country_codes_shuffled_copy = copy.deepcopy(country_codes_shuffled)
    measurements = subsets.keys()
    random.shuffle(measurements)
    for mmt in measurements:
        if not superset_paths:
            if not silent:
                print "Finished Early!"
            return mmts_ordered, nodes_covered
        if len(mmts_ordered) < len(country_codes_shuffled):
            if mmt in asn_to_cc and asn_to_cc[mmt] in countries_covered:
                continue
            if mmt not in asn_to_cc: continue
            gain = set(subsets_copy[mmt]).intersection(superset_paths)
            nodes_covered.append(list(gain))
            mmts_ordered.append(mmt)
            subsets_copy.pop(mmt)
            superset_paths = superset_paths.difference(gain)
            countries_covered.append(asn_to_cc[mmt])
        else:
            break
    # These are the left over measurements
    measurements = list(set(measurements).difference(set(mmts_ordered)))
    mmts_per_country = {}
    for mmt in measurements:
        if mmt not in asn_to_cc:
            print "ASN", mmt, "not in mapping"
            asn_to_cc[mmt] = 'XX'
        cc = asn_to_cc[mmt]
        if cc not in mmts_per_country:
            mmts_per_country[cc] = [mmt]
        else:
            mmts_per_country[cc].append(mmt)
        
    while superset_paths:
        random_cc = random.choice(mmts_per_country.keys())
        possible_mmts = mmts_per_country[random_cc]
        mmt = random.choice(possible_mmts)
        mmts_per_country[random_cc].remove(mmt)
        if not mmts_per_country[random_cc]:
            mmts_per_country.pop(random_cc)
        assert mmt not in mmts_ordered
        gain = set(subsets_copy[mmt]).intersection(superset_paths)
        nodes_covered.append(list(gain))
        mmts_ordered.append(mmt)
    subsets_copy.pop(mmt)
    superset_paths = superset_paths.difference(gain)
    return mmts_ordered, nodes_covered

def random_coverage(subsets, k, superset):
    print "Random selection"
    superset_paths = copy.deepcopy(superset)
    subsets_copy = copy.deepcopy(subsets)
    nodes_covered = []
    mmts_ordered = []
    measurements = subsets.keys()
    random.shuffle(measurements)
    for mmt in measurements:
        if not superset_paths:
            if not silent:
                print "Finished Early!"
            return mmts_ordered, nodes_covered
        gain = set(subsets_copy[mmt]).intersection(superset_paths)
    nodes_covered.append(list(gain))
    mmts_ordered.append(mmt)
    subsets_copy.pop(mmt)
    superset_paths = superset_paths.difference(gain)
    return mmts_ordered, nodes_covered

# wrapper for iterative_greedy_gen that returns only after the kth measurement
def iterative_greedy(k, superset, graph, probes):
    results = None
    for output in iterative_greedy_gen(k, superset, graph, probes):
        results = output
    return results

# generator that yields the coverage after each measurement
# saves the graph to disk after the last measurement
def iterative_greedy_gen(k, graph, probes, prefix):
    untested_probes = copy.deepcopy(probes)
    target = graph.gp.root
    #superset_paths = copy.deepcopy(superset)
    #num_known = len(superset_paths)
    asns_covered = set()
    for i in xrange(k):
        if not silent:
            print 'Measurement %d' % i
        '''if not superset_paths:
            if not silent:
                print "Found all {:d} known ASes, plus {:d} other ASes".format(num_known, len(nodes_covered))
            graph.save(os.path.join(save_dir, str(target) + '.gt'), fmt='gt')
            return mmts_ordered, nodes_covered'''
        next_prb_asn = get_next_best(graph, untested_probes, covered=asns_covered)
        del untested_probes[next_prb_asn]
        msmt_dag = None
        msmt_ids = None
        j = 0
        while not msmt_dag and j < len(probes[next_prb_asn]):
            next_prb = probes[next_prb_asn][j]
            msmt_dag = get_ripe_measurement.fetch_stored_measurement(target, next_prb, return_DAG=True)
            j += 1
        if not msmt_dag:
            j = 0
            while not msmt_ids and j < len(probes[next_prb_asn]):
                next_prb = probes[next_prb_asn][j]
                msmt_ids = get_ripe_measurement.create_measurements(prefix, [next_prb])
                j += 1
            if not msmt_ids:
                yield len(asns_covered)
                continue
            results = get_ripe_measurement.fetch_measurement(msmt_ids.keys()[0], 1, timeout=5, return_DAG=True)
            if next_prb not in results:
                yield len(asns_covered)
                continue
            msmt_dag = results[next_prb]
        for v in msmt_dag.vertices():
            v_asn = msmt_dag.vp.ASN[v]
            asns_covered.add(v_asn)
            asns_covered |= set(internet_tools.get_single_homed_customers(v_asn))
        yield len(asns_covered)
        graph.incorporate(msmt_dag)
    graph.save(os.path.join(save_dir, str(target) + '.gt'), fmt='gt')

def greedy_max_coverage(subsets, k, superset):
    superset_paths = copy.deepcopy(superset)
    subsets_copy = copy.deepcopy(subsets)
    nodes_covered = []
    mmts_ordered = []
    for i in xrange(k):
        if not superset_paths:
            print "Finished early!", i, k
            return mmts_ordered, nodes_covered
        max_gain = None
        max_gain_mmt = []
        for mmt in subsets_copy:
            if not max_gain:
                max_gain_mmt = mmt
                max_gain = set(subsets_copy[mmt]).intersection(superset_paths)
            if len(set(subsets_copy[mmt]).intersection(superset_paths)) > len(max_gain):
                max_gain = set(subsets_copy[mmt]).intersection(superset_paths)
                max_gain_mmt = mmt
        if not max_gain : pdb.set_trace()
        assert max_gain_mmt not in mmts_ordered
        superset_paths = superset_paths.difference(max_gain)
        nodes_covered.append(list(max_gain))
        if len(nodes_covered) > 1:
            print len(nodes_covered[-1]), len(nodes_covered[-2])
            assert len(nodes_covered[-1]) <= len(nodes_covered[-2])
        subsets_copy.pop(max_gain_mmt)
        mmts_ordered.append(max_gain_mmt)
    return mmts_ordered, nodes_covered

# runs and evaluates measurements for a given set of prefixes
# prefixes is an iterable of prefixes to test
# title is a string that describes the set of prefixes
metadata_dir = os.path.join(project_home, 'topology_discovery', 'iter_results')
if not os.path.exists(metadata_dir):
    os.makedirs(metadata_dir)
def evaluate_prefixes(prefix):
    #overall_mmt_gain = {}
    #overall_gain_content = set()
    if prefix == '0.0.0.0': return
    if not silent:
        print "Measuring towards %s" % prefix
    asn = ip2asn.ip2asn_bgp(prefix)
    if not asn:
        if not silent:
            print "NO ASN FOUND FOR PREFIX", prefix
        return
    if asn not in asn_graphs:
        if not silent:
            print "DO NOT HAVE ASN GRAPH OF PREF", prefix
        return
    if not silent:
        print "Prefix belongs to asn", asn
        print "Getting the ASN graph for", prefix
        print "Independently define the utilities of all paths from RIPE probes toward", prefix
    gr = asn_graphs[asn]
    with open(os.path.join(metadata_dir, prefix + '.csv'), 'w') as f:
        f.write('')
    for coverage in iterative_greedy_gen(sys.maxint, gr, probes_per_asn, prefix):
        with open(os.path.join(metadata_dir, prefix + '.csv'), 'a') as f:
            f.write(str(coverage) + '\n')
    '''root_vertex = gr.v_by_ASN(gr.gp.root)
    gr.filter_unlikely_edges()
    init_utility_per_mmt = {}
    superset = set() # contains all the nodes that can be covered if we were to run measurements from
    # all ripe nodes.
    for ripe_asn in probes_per_asn:
        gain = internet_tools.get_single_homed_customers(ripe_asn)
        probe_vertex = gr.v_by_ASN(ripe_asn)
        #overall_gain_content = overall_gain_content.union(set(gain))

        sp = set(gr.vp.ASN[v] for v in shortest_path(gr, probe_vertex, root_vertex)[0])

        utility = set(gain).union(sp)
        init_utility_per_mmt[str(ripe_asn)] = utility
        superset = superset.union(set(gain).union(set(sp)))
        
    measurement_gain = []
    #for k in xrange(1, len(init_utility_per_mmt) + 1):
    mmt_subset, coverage = greedy_max_coverage(init_utility_per_mmt,
                                               len(init_utility_per_mmt) + 1,
                                               superset)
    measurement_gain.append([mmt_subset, coverage])
    overall_mmt_gain[prefix] = measurement_gain

    with open("{:s}-{:s}-{:s}{:s}.json".format(title.replace(' ', '_'), type_probes, strategy, NOSH_str), "w") as fi:
        json.dump(overall_mmt_gain, fi)'''

if strategy == 'iterative':
    pool = Pool(processes=args.processes, maxtasksperchild=args.maxtasksperchild)
    for prefixes in [top_content_prefs, random_prefs.values(), top_cust_cone_prefs.values(), top_eyeball_prefs.values()]:
        for prefix in prefixes:
            #evaluate_prefixes(prefix)
            pool.apply_async(evaluate_prefixes, (prefix,))
    pool.close()
    pool.join()
else:
    evaluate_prefixes(top_content_prefs, "top content coverage")
    evaluate_prefixes(random_prefs.values(), "random coverage")
    evaluate_prefixes(top_cust_cone_prefs.values(), "top cust cone coverage")
    evaluate_prefixes(top_eyeball_prefs.values(), "top eyeball coverage")