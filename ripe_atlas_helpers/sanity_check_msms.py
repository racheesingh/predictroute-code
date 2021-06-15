import pdb
from ripe.atlas.cousteau import Probe, Measurement
import json
import sys

msm_fname = sys.argv[1]
with open(msm_fname) as fi:
    msms = json.load(fi)

msms_sane = []
for msm in msms:
    print msm
    try:
        info = Measurement(id=int(msm)).meta_data
    except:
        print "failed", msm
        msms_sane.append(msm)
        continue
    if info['status']['name'].strip().lower() == 'failed': continue
    if info['stop_time'] and int(info['stop_time']) < 1514764800: continue
    msms_sane.append(msm)

print len(msms), len(msms_sane)
with open(msm_fname + "_sane", "w") as fi:
    json.dump(msms_sane, fi)
    
