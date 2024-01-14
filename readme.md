#

it just ban which bt client in [blocklist](https://github.com/Asutorufa/transmission-auto-ban/blob/main/blacklist.go#L7).  
>maybe libtorrent and gt0003 need specify check method.  

## usage

```bash
transmission-auto-ban -rpc http://username@password:127.0.0.1:9091/transmission/rpc -host :9092 -file blocklist.txt -db blocklist.db
```

then enter `http://127.0.0.1:9092/blocklist.txt.gz` to transmission blacklist config.
