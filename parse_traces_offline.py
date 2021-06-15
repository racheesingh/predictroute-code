from consts import *
import dateutil.parser
import datetime
from copy import deepcopy
import ipaddress
import time
import os
import traceback
import multiprocessing as mp
import csv
from api import *
import json
import pdb
import sys
import bz2
node_gran = sys.argv[1] # should be 'asn', 'bgp_pfx' or 'pfx'

global_date = None
if len(sys.argv) > 2:
    global_date = sys.argv[2]
    
print "Global date:", global_date

fnames = glob.glob(RIPE_DAILY_DUMPS)
fnames.sort()
per_day_fnames = {}
for fname in fnames:
    day = fname.split('traceroute-')[-1].split('.bz2')[0].split('T')[0]
    if global_date:
        if day != global_date: continue
    if day not in per_day_fnames:
        per_day_fnames[day] = [fname]
    else:
        per_day_fnames[day].append(fname)

for day in sorted(per_day_fnames.keys()):
    print "Parsing traces for", day, len(per_day_fnames[day])
    # assert len(per_day_fnames[day]) == 24

    pool = mp.Pool(processes=6, maxtasksperchild=1)
    for fname in per_day_fnames[day]:
        print fname
        pool.apply_async(compute_dest_based_graphs_offline,
                         args=(fname, {}, node_gran,))
        #compute_dest_based_graphs_offline(fname, {}, node_gran)
    pool.close()
    pool.join()
