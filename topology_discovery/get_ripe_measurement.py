# standard libraries
import sys, pdb
import os.path
import re
from time import sleep
from datetime import datetime
from json import load, dumps

# non-standard libraries
from ripe.atlas.cousteau import ( #https://github.com/RIPE-NCC/ripe-atlas-cousteau
  Traceroute,
  AtlasSource,
  AtlasCreateRequest,
  AtlasResultsRequest
)
from ripe.atlas.sagan import Result
import radix

# local files
project_home = os.path.join(os.path.realpath(__file__), os.pardir)
project_home = os.path.abspath(os.path.join(project_home, os.pardir))
sys.path.append(project_home)
sys.path.append(os.path.join(project_home, 'tools'))
from DAG import *
import internet_tools
import mkit.inference.ixp as ixp
import mkit.ripeatlas.probes as prb

# CLI argument manager
parser = internet_tools.parser
silent = internet_tools.silent

parser.add_argument('-k', '--key', metavar='<your API key>', help='Your RIPE Atlas API key (required for creating requests)')

if __name__ == '__main__':
	parser.description='Create RIPE measurements, or fetch them from remote servers or local files'
	parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')

args = parser.parse_known_args()[0]

ATLAS_API_KEY = args.key

# run the first time parse_result is run
ixp_radix = None
private_addr_radix = None
def _parse_result_helper():
	global ixp_radix
	global private_addr_radix
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
			asn = internet_tools.ip2asn_bgp(ip)
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
					#this_hop_ases = None
					#continue
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
			if not silent:
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

def filter_cruft(data):
	if 'result' in data:
		res = data['result']
		for hop_idx, hop in enumerate( res ):
			if 'result' in hop:
				hop['result'] = [hr for hr in hop['result'] if 'edst' not in hr]
	return data

# takes a raw RIPE result and returns a DAG rooted at the last hop
# MMT_TYPE is used for evaluation, and should usually be more specific than "RIPE"
# optional ASN parameter is the ASN of the destination
#  if not provided, it will be looked up
# kwargs will be split into vertex properties and edge properties and passed on
# upon failure (for example, if the measurement didn't reach the dst), returns False
def parse_result(result, MMT_TYPE="RIPE", dst_asn=None, **kwargs):
	if not ixp_radix:
		_parse_result_helper()
	kwargs['timestamps'] = {'RIPE': result['endtime']}
	kwargs['RIPE_measurement_ID'] = result['msm_id']
	kwargs['RIPE_probe_ID'] = result['prb_id']

	vprops = {}
	eprops = {}
	for arg in kwargs:
		if arg in vp:
			vprops[arg] = kwargs[arg]
		if arg in ep:
			eprops[arg] = kwargs[arg]

	d = filter_cruft(result)
	if 'result' not in d:
		return False

	error = [x for x in d['result'] if 'error' in x]
	if error:
		return False
	if not 'dst_addr' in d:
		return False
	else:
		dst_addr = d['dst_addr']
		if not dst_asn:
			dst_asn = internet_tools.ip2asn_bgp(dst_addr)
	if not dst_addr:
		return False
	if not dst_asn:
		if not silent:
			print "Couldnt find this guys dst asn", dst_addr
		return False
	dst_asn = int(dst_asn)
	#print msm, dst_addr

	rnode = internet_tools.ip_to_pref(dst_addr)
	if rnode:
		dst_prefix = rnode.prefix.replace('/', '_')
	else:
		return False
	G = new_DAG(prefix=dst_prefix, ASN=dst_asn, mmt_type=MMT_TYPE, **vprops)
	root_node = G.v_by_ASN(G.gp.root)

	src_asn = prb.get_probe_asn(d['prb_id'])
	if not src_asn:
		return False

	iplinks = Result.get(d)
	aslinks = parse_traceroute(iplinks, src_asn)
	#aslinks = asp.traceroute_to_aspath(d)
	nodes = aslinks['_nodes']
	if not aslinks['_links']:
		return False

	# Simple Sibling check, if trace did not complete but the last hop
	# is sibling, we can consider
	# the trace did reach its destination
	if aslinks['_links'][-1]['dst'] != str(dst_asn):
		if internet_tools.are_siblings(aslinks['_links'][-1]['dst'], dst_asn):
			if not silent:
				print "Final hop was a sibling of the destination, replacing with dstasn", \
					aslinks['_links'][-1]['dst'], dst_asn
			aslinks['_links'][-1]['dst'] = dst_asn
			
	if aslinks['_links'][-1]['src'] == aslinks['_links'][-1]['dst']:
		if not silent:
			print "The last link ended up being either the sibling destination as src and dst"
			print "or the destination AS as src and dst"
		if aslinks['_links'][-1]['src'] == dst_asn:
			aslinks['_links'] = aslinks['_links'][:-1]
		else:
			pdb.set_trace()
	if '_ixps' in aslinks:
		identified_ixps = dict(aslinks['_ixps'])
	else:
		identified_ixps = []
	if not aslinks['_links']:
		return False
	if str(dst_asn) not in ixp.IXPs:
		try:
			aslinks = ixp.remove_ixps(aslinks)
		except (IndexError, AssertionError):
			return False
	else:
		if not silent:
			print "Are you kidding me?"
		aslinks = aslinks['_links']
	if not aslinks:
		return False
	path_list = []
	for link in aslinks:
		path_list.append(link['src'])

	path_list.append(link['dst'])
	if path_list[-1] != str(dst_asn):
		path_list.append("*")
		path_list.append(str(dst_asn))
	prev_vertex = None
	for link in aslinks:
		if int(link['src']) == dst_asn:
			break
		v1 = G.v_by_ASN(link['src'])
		if not v1:
			v1 = G.add_vertex(ASN=link['src'], mmt_type=MMT_TYPE, **vprops)

		v2 = G.v_by_ASN(link['dst'])
		if not v2:
			v2 = G.add_vertex(ASN=link['dst'], mmt_type=MMT_TYPE, **vprops)

		# Identified as an IXP
		if link['dst'] in identified_ixps:
			G.vp.ixp[v2] = True
			ixpmatch =  ixp_radix.search_best(link['dst'])
			if ixpmatch:
				G.vp.prefix[v2] = ixpmatch.prefix
		if link['src'] in identified_ixps:
			G.vp.ixp[v1] = True
			ixpmatch = ixp_radix.search_best(link['src'])
			if ixpmatch:
				G.vp.prefix[v1] = ixpmatch.prefix

		assert G.vp.ASN[v1] == int(link['src'])
		assert G.vp.ASN[v2] == int(link['dst'])
		ed = G.edge(v1,v2)
		if not ed:
			ed = G.add_edge(v1, v2, **eprops)
		if not prev_vertex:
			key = "gen"
			G.vp.measurements_generated[v1] += 1
			G.vp.path[v1] = path_list
		else:
			key = prev_vertex
		if key in G.ep.previous_vertexes[ed]:
			G.ep.previous_vertexes[ed][key] += 1
		else:
			G.ep.previous_vertexes[ed][key] = 1
		if link['type'] == 'i':
			G.ep.indirect[ed] = True
		else:
			G.ep.indirect[ed] = False
		prev_vertex = link['src']
		if int(link['dst']) == int(dst_asn):
			break

	assert root_node.out_degree() == 0

	return G

# returns raw ripe measurements under a given msm_id
# num_probes is the number of probes used in the measurement
# timeout is the maximum amount of time, in MINUTES, to wait for results
# breakpoint is the maximum proportion of results to fetch before returning
# returns a dictionary from probe IDs to results if return_DAG is false
# otherwise returns a dictionary from probe IDs to DAG objects
def fetch_measurement(msm_id, num_probes, timeout=10, breakpoint=0.9, return_DAG=False):
	assert breakpoint <= 1 and breakpoint >= 0, "breakpoint must be a proportion (between 0 and 1 inclusive)"
	timeout *= 2
	half_mins_passed = 0
	results = []
	while half_mins_passed < timeout and len(results)*breakpoint < num_probes:
		half_mins_passed += 1
		is_success, results = AtlasResultsRequest(msm_id=msm_id).create()
		if not is_success:
			if not silent:
				print 'Fetching result from msm_id {:s} failed'.format(str(msm_id))
				print results
			pdb.set_trace()
		if len(results) >= num_probes:
			if not silent:
				print "All {:d} probes returned before {:.1f} minutes for measurement {:s}".format(num_probes, float(half_mins_passed/2.0), str(msm_id))
			break
		sleep(30)
	all_results = {}
	for result in results:
		store_measurement(result)
		if return_DAG:
			dag = parse_result(result, MMT_TYPE='RIPE-custom')
			if dag:
				all_results[result['prb_id']] = dag
		else:
			all_results[result['prb_id']] = result
	return all_results

# creates a measurement from RIPE atlas
# target is the ipv4 address or ipv4 prefix towards which to measure
# all_probes is an iterable of probe IDs from which to run measurements
# returns False upon failure, or a dictionary of msm_ids to number of probes used in that measurment upon success
ipv4_re = re.compile('(?P<first>(?:[0-9]{1,3}\.){3})(?P<fourth>[0-9]{1,3})')
def create_measurements(target, all_probes):
	assert ATLAS_API_KEY, "A RIPE Atlas API key is required to create a measurement"
	# if the target is a prefix, convert it to an address
	if '_' in target:
		match = ipv4_re.match(pref)
		target = match.group('first') + str(int(match.group('fourth')) + 1)

	traceroute = Traceroute(
		af=4,
		target=target,
		description="PC",
		protocol="ICMP",
	)

	msm_ids = {}
	# RIPE can't handle requests from more than 1000 probes at once, so split the requests up
	for i in xrange(len(all_probes)/1000 + 1):
		probes = [int(pr) for pr in all_probes[i*1000:(i+1)*1000]]
		num_probes = len(probes)
		csv_ids = ','.join(str(i) for i in probes)

		source = AtlasSource(type="probes", value=csv_ids, requested=num_probes)

		now = datetime.utcnow()

		atlas_request = AtlasCreateRequest(
			start_time=now,
			key=ATLAS_API_KEY,
			measurements=[traceroute],
			sources=[source],
			is_oneoff=True
		)

		(is_success, response) = atlas_request.create()
		if not is_success:
			if not silent:
				print 'Measurement to {:s} failed'.format(target)
				print response
			return False
		msm_ids[response['measurements'][0]] = num_probes

	return msm_ids

# fetches a measurement stored on disk
# target is the ip address or prefix or ASN of the target
# prb_id is the ID of the probe that made that measurement
# if return_DAG is True return a DAG, otherwise return the raw result
# returns False upon failure
file_dir = os.path.dirname(os.path.abspath(__file__))
mmt_dir = os.path.join(file_dir, 'measurements')
if not os.path.exists(mmt_dir):
	os.makedirs(mmt_dir)
def fetch_stored_measurement(target, prb_id, return_DAG=False):
	try:
		target = int(target)
	except:
		target = internet_tools.ip2asn_bgp(target)
		if not target:
			return False
	try:
		with open(os.path.join(mmt_dir, str(target) + '.json'), 'r') as f:
			result = load(f)[str(prb_id)]
	except IOError:
		if not silent:
			print "No stored measurements towards ASN {:d}".format(target)
		return False
	except ValueError:
		if not silent:
			print "The measurement file for ASN {:d} is mal-formed".format(target)
		return False
	except KeyError:
		'''if not silent:
			print "There is no stored measurement from probe {:s} to ASN {:d}".format(str(prb_id), target)'''
		return False
	if return_DAG:
		return parse_result(result)
	return result

# stores a raw result on disk
# result is the result to be stored
# target is the ip address or prefix or ASN of the target. If not included, it is inferred from the result
# returns whether it succeeds
def store_measurement(result, target=None):
	if not target:
		target = result['dst_addr']
	try:
		target = int(target)
	except:
		target = internet_tools.ip2asn_bgp(target)
		if not target:
			if not silent:
				print "ASN not found for target"
			return False

	prb_id = result['prb_id']

	try:
		with open(os.path.join(mmt_dir, str(target) + '.json'), 'w+') as f:
			try:
				json_results = load(f)
				json_results[str(prb_id)] = result
			except (ValueError, IOError):
				json_results = {str(prb_id): result}
			f.write(dumps(json_results))
		return True
	except Exception as e:
		print e
		return False