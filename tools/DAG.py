# non-standard libraries
from graph_tool.all import Graph, load_graph # https://graph-tool.skewed.de
from graph_tool.util import find_vertex, find_edge # https://graph-tool.skewed.de

# list of data sources
data_sources = ['RIPE', 'CAIDA', 'BGPSim']

# vertex properties of a DAG
# each property is included as <property name> : (<type>, <default>)
vp = {
	  'ASN': ('int', None),
	  'prefix': ('string', None),
	  'duplicate_id': ('int', 0), # ordinality of this vertex as a duplicate (first one for this ASN is 0, second is 1....)
	  'measurements_generated': ('int', 0), # number of traceroutes for which this vertex is the vantage point
	  'timestamps': ('object', {data_source: 0 for data_source in data_sources}), # dictionary of measurement sources to UNIX timestamps
	  'RIPE_measurment_ID': ('long', -1), # measurement ID of the latest RIPE measurement to see this node (if any)
	  'RIPE_probe_ID': ('int', -1), # probe ID of the lastest RIPE probe to see this node (if any)
	  'mmt_type': ('object', set()), # used for evaluation
	  'path': ('vector<string>', []), # The latest measured path that this vertex was involved in
	  'ixp': ('bool', False) # whether the vertex is in an IXP
	  }

# edge properties of a DAG
# each property is included as <property name> : (<type>, <default>)
ep = {
	  'timestamps': ('object', {data_source: 0 for data_source in data_sources}), # dictionary of measurement sources to UNIX timestamps
	  'indirect': ('bool', False), # False if this edge is definitely direct, True if it may be indirect (holes in the traceroute)
	  'RIPE_measurment_ID': ('long', -1), # measurement ID of the latest RIPE measurement to see this edge (if any)
	  'RIPE_probe_ID': ('int', -1), # probe ID of the lastest RIPE probe to see this edge (if any)
	  'previous_vertexes': ('object', {}) # Dictionary of prior hop vertex ASN (one before e.source()) to frequencies
	  }

# graph properties of a DAG
# each property is included as <property name> : <type>
gp = {
	  'prefix': 'string', # the prefix that this is the DAG towards
	  'root': 'int' # reference to the root vertex descriptor
	  }

def load_DAG(filename, fmt='auto'):
	g = DAG(g=load_graph(filename, fmt))
	for vprop in vp:
		assert vprop in g.vp
	for eprop in ep:
		assert eprop in g.ep
	for gprop in gp:
		assert gprop in g.gp
	return g

# factory for DAGs. Use this instead of the constructor
# creates a Graph object and initializes PropertyMaps
# takes the prefix and the ASN of the root, plus any other properties of the root as kwargs
def new_DAG(ASN, prefix=None, **kwargs):
	g = DAG()
	ASN = int(ASN)
	for prop in vp:
		vprop = g.new_vertex_property(vp[prop][0], val=vp[prop][1])
		g.vertex_properties[prop] = vprop

	for prop in ep:
		eprop = g.new_edge_property(ep[prop][0], val=ep[prop][1])
		g.edge_properties[prop] = eprop

	for prop in gp:
		gprop = g.new_graph_property(gp[prop])
		g.graph_properties[prop] = gprop

	if prefix:
		g.gp.prefix = prefix

	root = g.add_vertex(ASN=ASN, **kwargs)

	g.gp.root = ASN

	return g


# a subclass of graph_tool's Graph class with some useful functions
class DAG(Graph):

	# can be called internally with a graph parameter g for loading from a file
	def __init__(self, g=None):
		Graph.__init__(self, g)


	# returns the vertex whose ASN is ASN
	# returns False if there is no such vertex
	def v_by_ASN(self, ASN):
		ASN = int(ASN)
		try:
			return find_vertex(self, self.vp.ASN, ASN)[0]
		except IndexError:
			return False

	def get_root(self):
		return self.v_by_ASN(self.gp.root)

	# wraps the Graph method of the same name
	# source and target can be ASNs or vertex descriptors
	def edge(self, source, target):
		for vertex in (source, target):
			if type(vertex) == type(''):
				vertex = int(vertex)
			if type(vertex) == type(1):
				ASN = vertex
				vertex = self.v_by_ASN(ASN)
				if not vertex:
					return False
		return Graph.edge(self, source, target)

	# adds a new vertex, assigning it values from kwargs if provided
	# or default values otherwise
	def add_vertex(self, **kwargs):
		# ASNs should be ints
		if 'ASN' in kwargs:
			kwargs['ASN'] = int(kwargs['ASN'])
		# mmt_types should be sets
		if 'mmt_type' in kwargs and type(kwargs['mmt_type']) != type(set()):
			kwargs['mmt_type'] = set([kwargs['mmt_type']])
		# not all timestamps need be specified; incomplete dicts are acceptable
		if 'timestamps' in kwargs:
			for source in kwargs['timestamps']:
				kwargs['timestamps'][source] = int(kwargs['timestamps'][source])
			for source in data_sources:
				if source not in kwargs['timestamps']:
					kwargs['timestamps'][source] = 0
		# correct for strange types for mmt_types
		if 'mmt_types' in kwargs:
			if hasattr(kwargs['mmt_types'], '__iter__') \
			 and type(kwargs['mmt_types']) != type(''):
				kwargs['mmt_types'] = set(kwargs['mmt_types'])
			else:
				kwargs['mmt_types'] = set([kwargs['mmt_types']])
		# actually create the vertex
		v = Graph.add_vertex(self)
		for vprop in vp:
			if vprop in kwargs:
				self.vertex_properties[vprop][v] = kwargs[vprop]
			else:
				self.vertex_properties[vprop][v] = vp[vprop][1]
		return v

	# adds a new edge between source and target,
	# assigning it values from kwargs if provided
	# or default values otherwise
	# source and target can each be an int, in which case they are an ASN
	# or they can be vertex descriptors
	def add_edge(self, source, target, **kwargs):
		# not all timestamps need be specified; incomplete dicts are acceptable
		if 'timestamps' in kwargs:
			for src in data_sources:
				if src not in kwargs['timestamps']:
					kwargs['timestamps'][src] = 0
		# if source or target are ASNs, get the equivalent vertex descriptors
		# or create them if they don't yet exist
		for vertex in (source, target):
			if type(vertex) == type(''):
				vertex = int(vertex)
			if type(vertex) == type(1):
				ASN = vertex
				vertex = self.v_by_ASN(ASN)
				if not vertex:
					vertex = self.add_vertex(ASN=ASN)
		# add the edge
		e = Graph.add_edge(self, source, target)
		for eprop in ep:
			if eprop in kwargs:
				self.edge_properties[eprop][e] = kwargs[eprop]
			else:
				self.edge_properties[eprop][e] = ep[eprop][1]
		return e

	# adds a vertex from a vetex descriptor
	# v is the vertex descriptor, g is its containing DAG
	# returns the vertex descriptor
	def incorporate_vertex(self, v, g):
		ASN = g.vp.ASN[v]
		# check if the vertex already exists in the DAG
		local_v = self.v_by_ASN(ASN)
		if local_v:
			# if it does, merge the two
			if self.vp.timestamps[local_v]['RIPE'] < g.vp.timestamps[v]['RIPE']:
				# if e has a newer RIPE measurement, update the RIPE metadata
				self.vp.RIPE_measurment_ID[local_v] = g.vp.RIPE_measurment_ID[v]
				self.vp.RIPE_probe_ID[local_v] = g.vp.RIPE_probe_ID[v]
			for data_source in data_sources:
				self.vp.timestamps[local_v][data_source] = \
					min(self.vp.timestamps[local_v][data_source], g.vp.timestamps[v][data_source])
			self.vp.measurements_generated[local_v] += g.vp.measurements_generated[v]
			self.vp.mmt_type[local_v] |= g.vp.mmt_type[v]
		else:
			# otherwise, add the new vetex
			local_v = Graph.add_vertex(self)
			for vprop in vp:
				self.vertex_properties[vprop][local_v] = g.vertex_properties[vprop][v]
		return local_v

	# adds an edge from an edge descriptor
	# e is the edge descriptor, g is its containing DAG
	# returns the edge descriptor
	def incorporate_edge(self, e, g):
		local_source = self.incorporate_vertex(e.source(), g)
		local_target = self.incorporate_vertex(e.target(), g)
		# check if the edge already exists in the DAG
		local_e = self.edge(local_source, local_target)
		if local_e:
			# if it does, merge the two
			if self.ep.timestamps[local_e]['RIPE'] < g.ep.timestamps[e]['RIPE']:
				# if e has a newer RIPE measurement, update the RIPE metadata
				self.ep.RIPE_measurment_ID[local_e] = g.ep.RIPE_measurment_ID[e]
				self.ep.RIPE_probe_ID[local_e] = g.ep.RIPE_probe_ID[e]
			for data_source in data_sources:
				self.ep.timestamps[local_e][data_source] = \
					min(self.ep.timestamps[local_e][data_source], g.ep.timestamps[e][data_source])
			self.ep.indirect[local_e] |= g.ep.indirect[e]
			for ASN in g.ep.previous_vertexes[e]:
				if ASN in self.ep.previous_vertexes[local_e]:
					self.ep.previous_vertexes[local_e][ASN] += g.ep.previous_vertexes[e][ASN]
				else:
					self.ep.previous_vertexes[local_e][ASN] = g.ep.previous_vertexes[e][ASN]
		else:
			# otherwise, create a new vertex with the same properties as e
			local_e = self.add_edge(local_source, local_target)
			for eprop in ep:
				self.edge_properties[eprop][local_e] = g.edge_properties[eprop][e]

	# merges another DAG into this one
	# other is a reference to another DAG
	def incorporate(self, other):
		for e in other.edges():
			self.incorporate_edge(e, other)
		return self

	# filters BGPSim edges that compete with measured edges
	# undo using g.clear_filters(), inherited from Graph
	def filter_unlikely_edges(self):
		filter_prop = self.new_edge_property("bool", val=True)
		for v in self.vertices():
			if v.out_degree() <= 1:
				continue
			timestamps = {e: self.ep.timestamps[e] for e in v.out_edges()}
			# check whether a measured edge exists
			measured = False
			for e in timestamps:
				measured |= timestamps[e]['RIPE'] > 0
				measured |= timestamps[e]['CAIDA'] > 0
			if not measured:
				return
			for e in timestamps:
				filter_prop[e] = (timestamps[e]['RIPE'] != 0 or timestamps[e]['CAIDA'] != 0)
			self.set_edge_filter(filter_prop)