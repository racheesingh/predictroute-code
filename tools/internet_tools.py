# standard libraries
import argparse
from datetime import datetime
import os, sys
import re
from json import load

# non-standard libraries
import radix # https://pypi.org/project/py-radix/

# local files
project_home = os.path.join(os.path.realpath(__file__), os.pardir)
project_home = os.path.abspath(os.path.join(project_home, os.pardir))
sys.path.append(project_home)
from settings import * # contains default paths

# command line argument management
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Create and serialize DAGs from RIPE atlas measurments')
else:
	parser = argparse.ArgumentParser(add_help=False)

# checks whether a file can be read without opening it
def _file_check(f):
	if not os.path.isfile(f):
		raise IOError("[Errno 2] No such file or directory: '%s'" % f)
	if not os.access(f, os.R_OK):
		raise IOError("[Errno 13] Permission denied: '%s'" % f)
	return f


parser.add_argument('-s', '--silent', action='store_true',
					help='If included, nothing will be printed to standard out')
parser.add_argument('--pfx2as', type=_file_check, metavar='<pfx2as file path>',
					default=default_pfx2as_file,
					help='Path to the .pfx2as file that converts prefixes to ASes')
parser.add_argument('--as2org', type=_file_check, metavar='<as2org file path>',
					default=default_as2org_file,
					help='Path to the .pfx2as file that converts ASes to organizations')
parser.add_argument('--as_rel', type=_file_check, metavar='<as_rel file path>',
					default=default_as_rel_file,
					help='Path to the .as-rel.txt file that contains the relationships between ASes')
parser.add_argument('--asn_to_cc', type=_file_check, metavar='<as_to_cc file path>',
					help='Path to the as_to_cc json file that contains a dictionary from ASN to country code')
parser.add_argument('--nosh', action='store_true',
					help='If included, this program will ignore gains by assuming single homed ASNs route through thier provider. ' \
						 'This can greatly improve performance.')


args = parser.parse_known_args()[0]

pfx2as_file = args.pfx2as
as2org_file = args.as2org
as_rel_file = args.as_rel
asn_to_cc_file = args.asn_to_cc
silent = args.silent
NOSH = args.nosh

# create a radix tree from prefix to ASNs
rtree_bgpv4 = False
def _construct_rtree():
	global rtree_bgpv4
	rtree_bgpv4 = radix.Radix()
	asn_to_pfxs = {}
	with open(pfx2as_file, 'rb') as pfx2as:
		for line in pfx2as:
			ip, preflen, asn = line.split()
			if asn in asn_to_pfxs:
				asn_to_pfxs[asn].append("%s/%s" % (ip, preflen))
			else:
				asn_to_pfxs[asn] = ["%s/%s" % (ip, preflen)]
			if ',' in asn:
				tokens = asn.split(',')
				asn = tokens[0]
			if '_' in asn:
				tokens = asn.split('_')
				asn = tokens[0]
			rnode = rtree_bgpv4.add(network=ip, masklen=int(preflen))
			rnode.data["asn"] = asn

ipv4_re = re.compile('(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
# converts an ip address to an ASN using BGP data
# v6 doesn't work :P
def ip2asn_bgp(ip, v6=False):
	if not rtree_bgpv4:
		_construct_rtree()
	if v6:
		try:
			node = rtree_bgpv6.search_best(ip)
		except ValueError:
			if not silent:
				print "Could not get AS for IP", ip
			return None
	else:
		try:
			ip = ipv4_re.match(ip).group(0)
		except AttributeError:
			if not silent:
				print "Improperly formatted ipv4 address", ip
			return None
		try:
			node = rtree_bgpv4.search_best(ip)
		except ValueError:
			if not silent:
				print "Could not get AS for IP", ip
			return None
	if node:
		return node.data['asn']
	else:
		return None

# finds the prefix under which an ip address was announced
def ip_to_pref(ip):
	if not rtree_bgpv4:
		_construct_rtree()
	try:
		node = rtree_bgpv4.search_best(ip)
	except ValueError:
		print "Could not get prefix for IP", ip
		return None

	if node:
		return node
	else:
		return None

# creates a dictionary of ASes to organization IDs
# run the first time are_siblings is invoked
orgs = {}
def _are_siblings_helper():
	global orgs
	now = '-'.join(str(datetime.now() ).split())
	with open(as2org_file, 'rb') as as2org:
		for line in as2org:
			# ignore commented lines
			if line[0] == "#":
				continue
			tokens = line.rstrip().split('|')
			# aut|changed|name|org_id|source
			if tokens[0].isdigit():
				asn = int(tokens[0])
				orgs[asn] = tokens[3]

# returns True if as1 and as2 are siblings, False otherwise
# as1 and as2 should be AS numbers
def are_siblings(as1, as2):
	if not orgs:
		_are_siblings_helper()
	as1 = int(as1)
	as2 = int(as2)
	if not silent:
		print "Checking if siblings:", as1, as2
	if as1 not in orgs or as2 not in orgs:
		return False
	return orgs[ as1 ] == orgs[ as2 ]

# customers of an asn
customer_asns = {}
#list of single-homed ASNs
single_homed_asns = None
def _get_single_homed_customers_helper():
	global single_homed_asns
	global customer_asns
	# providers of an asn
	provider_asns = {}
	with open(as_rel_file, 'r') as f:
		for line in f:
			if line.startswith('#'): continue
			try:
				prov, cust, typ, src = line.split('|')
				typ = int(typ)
			except ValueError:
				prov, cust, typ = line.split('|')
				typ = int(typ[:-1])
			prov = int(prov)
			cust = int(cust)
			if typ == -1:
				if cust in provider_asns:
					provider_asns[cust].append(prov)
				else:
					provider_asns[cust] = [prov]
				if prov in customer_asns:
					customer_asns[prov].append(cust)
				else:
					customer_asns[prov] = [cust]
			else:
				# Treating p2p as provider links that go both
				# ways. Since I want to find ASNs that have *only*
				# one way to go outside of their network
				if cust in provider_asns:
					provider_asns[cust].append(prov)
				else:
					provider_asns[cust] = [prov]
				if prov in provider_asns:
					provider_asns[prov].append(cust)
				else:
					provider_asns[prov] = [cust]
					
	single_homed_asns = [int(x[0]) for x in provider_asns.items() if len(x[1]) == 1]

# returns a list of single-homed customers of the AS with ASN asn
def get_single_homed_customers(asn):
	if NOSH:
		if not silent:
			print "Single homed customers turned off."
		return []
	if not single_homed_asns:
		if not silent:
			print "Retreiving single-homed ASNs"
		_get_single_homed_customers_helper()
	if int(asn) not in customer_asns:
		return []
	single_homed = set()
	for cust in customer_asns[int(asn)]:
		if cust in single_homed_asns:
			single_homed.add(cust)
	return list(single_homed)

# returns a set of all asns
asns = set()
def get_asns():
	global asns
	if asns:
		return asns
	with open(as_rel_file, 'r') as f:
		for line in f:
			if line.startswith('#'): continue
			src, dst, typ = line.split('|')
			asns.add(int(src))
			asns.add(int(dst))
	return asns

# country codes translation
asn_to_cc_dict = {}
def _establish_country_codes():
	global asn_to_cc_dict
	assert asn_to_cc_file, 'No ASN to country code file provided. Use the "--asn_to_cc" option'
	with open(asn_to_cc_file, 'r') as f:
		asn_to_cc_dict = load(f)

# returns the country code associated with the given ASN
def asn_to_cc(asn):
	if not asn_to_cc_dict:
		_establish_country_codes
	return asn_to_cc_dict[asn]