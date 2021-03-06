## Predictroute

1. To Start using Predictroute, follow these steps:
2. Create a file `consts.py` with directories that contain your traceroute datasets. The location of the traceroutes is used in `api.py`.
3. Download RIPE traceroutes either from the RIPE measurement page or from the FTP link with daily dumps of public traces.
4. Store RIPE traces at a location defined in `consts.py` called `RIPE_DAILY_DUMPS`.
5. `parse_traces_offline.py` will create several processes to parse these daily dumps, one for each day's compressed traceroutes. This code mainly refers to `compute_dest_based_graphs_offline` which has much of the logic for parsing large quantities of traceroute data in parallel, creating graphs at prefix or ASN level and committing them to disk.
6. The graphs are stored in `.gt` format which can be opened using the `graph-tool` library.
7. Once the graphs for a single day's worth of traces are stored, they are combined with graphs from before. This job is done by `combine_dags_src_dst.py`.
8. The processes of downloading, parsing, building graphs  and combining them with previous graphs can be easily made into cron jobs. Shell scripts to run this code are also checked into the repo.