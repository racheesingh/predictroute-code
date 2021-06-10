import beanstalkc
import multiprocessing as mp
import calendar
from copy import deepcopy
import time
import datetime
import os
import traceback
import multiprocessing as mp
import csv
from api import *
import json
import pdb
import sys
import glob

#dirnames = glob.glob("/srv/data1/rachee/historical/all/%s/2019-11*" % node_gran)
#dirnames = glob.glob("/srv/data1/rachee/historical/all/%s/2019-12*" % node_gran)
#dirnames.append("/srv/data1/rachee/historical/all/complete_graphs_v2_march")
#dirnames.append("/srv/data2/rachee/complete_graphs_v2")
#dirnames.sort()
today = datetime.date.today()
parse_days = 7
dirnames = []
while parse_days > 0:
    day_datetime = today - datetime.timedelta(days=parse_days)
    parse_days -= 1
    str_date = day_datetime.strftime("%Y-%m-%d")
    print str_date
    dirnames.extend(glob.glob("/srv/data1/rachee/historical/all/bgp_pfx/%s*" % str_date))
    
portnum = int(sys.argv[1])
# dirname_regexes = sys.argv[2:]
# dirnames = []
# for dregex in dirname_regexes:
#     dirnames.extend(glob.glob(dregex))

dirnames.sort()
dirnames = ['/srv/data2/rachee/pc_combined_graphs/bgp_pfx_old/'] + dirnames
all_idens = {}
for dirname in dirnames:
    fnames = glob.glob(dirname + '/*.gt')
    print dirname, len(fnames)
    idens = [x.split('/')[-1].split('.gt')[0] for x in fnames]
    for iden in idens:
        if iden not in all_idens:
            all_idens[iden] = [dirname + "/%s.gt" % iden]
        else:
            all_idens[iden].append(dirname + "/%s.gt" % iden)

beanstalk = beanstalkc.Connection(host='localhost', port=portnum)
for iden in all_idens:
    print "Adding:", iden
    beanstalk.put("%s:" % iden + ",".join(all_idens[iden]))

beanstalk.close()

