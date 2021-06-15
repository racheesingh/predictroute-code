import os
import pdb
import glob

caida_relevant_files = filter(os.path.isfile, glob.glob("data2/caida/" + "*"))
timestamps = []
for fname in caida_relevant_files:
    ts = fname.split('/')[-1].split('.')[0]
    timestamps.append(ts)

timestamps = sorted([x for x in timestamps if x > '20080000'])
graphs_per_month = {}
for ts in timestamps:
    if ts != '20170201': continue
    as_rel_fname = [x for x in caida_relevant_files if ts + '.as-rel' in x]
    assert len(as_rel_fname) == 1
    as_rel_fname = as_rel_fname[0]
    with open(as_rel_fname) as f:
        with open("data2/caida/cyclops/%s-cyclops" % ts, "w") as fi:
            for line in f:
                if line.startswith('#'): continue
                src, dst, typ = line.split('|')
                typ = typ.strip()
                if typ == '-1':
                    type_new = 'p2c'
                else:
                    type_new = 'p2p'
                fi.write("%s\t%s\t%s\n" % (src, dst, type_new))
