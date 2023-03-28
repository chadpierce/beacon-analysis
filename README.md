# C2 Beacon Analysis Tools

This repo contains a few utilities that take logs from any data source you'd like in some delimited flat file.  
The intent is for this to be generic and work against any log source.  

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

Currently, the Go version is the most interesting to me because the use of goroutines speeds up analysis quite a bit.  
The lack of Python dependencies and portable binaries is a bonus.  

## Usage

Default values are currently in play, but options can be modified using the arguments listed below.  
There are default parameters that work for me, but most can be modified by passing arguments.  

```
Usage of program:
Usage of program:
  -B    do not use bytes sent/received in analysis
  -D    use DNS Log CSV Inputs (no size analysis)
  -O    write output to inputfilename.out
  -P    use Proxy Log CSV Inputs
  -S float
        minimum score threshold (default 0.5)
  -X    [TODO] enable debug mode for extra output
  -cd int
        csv column for destination (default 7)
  -cr int
        csv column for bytes recevied (default 11)
  -cs int
        csv column for source (default 2)
  -ct int
        csv column for timestamp (default 0)
  -cx int
        csv column for bytes sent (default 12)
  -d string
        input csv delimiter (put in quotes: ';' (default ",")
  -h    display help
  -i string
        input csv filename
  -m int
        minimum number of connections threshold (default 36)
  -o string
        write output to given filename
  -s int
        maximum number of sources for destination threshold (default 5)
  -wc float
        weight value connection count score (default 1)
  -wm float
        weight value for MADM score (default 1)
  -ws float
        weight value for skew score (default 1)
  -wz float
        weight value for data size score (default 1)
```

## TODO

- Tune default scoring
- Tune algorithm outputs
- Add customizable thresholds for the 4 scoring systems
- Add input arguments with optional values for those thresholds
- If this is useful, write more documentation (if it wasn't useful it was a fun experiement)
- ignore input lines that don't start with proper date format? - print warning to screen
- add start/stop time for session (and duration) to output, potentially use for scoring
- debug mode that prints all datapoints for each pair
- Create a DNS log generator