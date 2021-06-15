import urllib2
import json
import pdb
import urllib
from datetime import datetime
import time


API_HOST = "https://atlas.ripe.net"
API_MMT_URI = 'api/v2/measurements'
def fetch_json(offset=1, id_gte=0):
    data = []
    api_args = dict(page=offset,
                    af=4,
                    status=4,
                    type="traceroute",
                    start_time_gte=1517443200,
                    id__gt=id_gte)        
    url = "%s/%s/?%s" % (API_HOST, API_MMT_URI, urllib.urlencode(api_args))
    print url
    response = urllib2.urlopen(url)
    data = json.load(response)
    return data

def get_all_measurements():
    msms_old = []
    max_id = 0
    count = 1
    while(1):
        try:
            data = fetch_json(offset=count, id_gte=max_id)
            if not data: break
            for d in data['results']:
                msms_old.append(d['id'])
            count += 1
        except urllib2.HTTPError:
            max_id = max(msms_old)
            count = 1
        print len(msms_old)
    return msms_old

msms = get_all_measurements()

with open("all_v4_traces_ripe_1496275200.json", "w") as fi:
    json.dump(msms, fi)
