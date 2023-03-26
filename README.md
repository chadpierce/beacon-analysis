# C2 Beacon Analysis Tools

This repo contains a few utilities that take logs from any data source you'd like in .csv format. The intent is for this to be generic

Currently, the following files exist:

    - `beacon_finder.py` - this is a Python script based on a Jupyter Notebook implementation of RITA (https://github.com/activecm/rita).  
    - `beacon_finder.go` - this is based on the Python script above, and is mostly written by the Bing Chat AI
    - `proxy_log_generator.py` - this generates dummy proxy log data with a single beacon for testing

For each version, the input file must include:  
    
    - a timestamp (hard coded format for now)
    - a source (e.g. username / IP / hostname)
    - a destination (e.g. IP / domain)
    - bytes received
    - bytes sent

Currently, the Go version is the most interesting to me because the use of goroutines speeds up analysis quite a bit on test data.  
YMMV on production data that is huge. The lack of Python dependencies and portable binaries is a bonus. 

## TODO

- If this is useful, write more documentation (if it wasn't useful it was a fun experiement)
- Create a DNS log generator
- Add input arguments with optional values:
    - filename
    - various thresholds
    - help
    - toggle data / time analysis
    - customize input fields
- combine time and data beacon scores into a single score