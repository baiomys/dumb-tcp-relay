[![Go Report Card](https://goreportcard.com/badge/github.com/baiomys/dumb-tcp-relay)](https://goreportcard.com/report/github.com/baiomys/dumb-tcp-relay)

## Command line switches  
  -c config file 
  -q quiet mode 

## Host priorities in MX are not taken into account when iterating through the list of IPs.

Example config.json
```
{
  "listen_addr": ":25",
  "target_port": "2525",
  "remote_ips": ["192.168.1.45", "10.126.12.2"],
  "mx_domain": "split.it.example.com",
  "timeout": 30,
  "buffer_size": 8192,
  "resolve_mx": false,
  "resolve_freq": 5,
  "rate_limit": 100,
  "rate_limit_window": 60
}
```
