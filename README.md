# DNS client test
The DNS-client-test program resolves domains listed in a file at a configurable request rate and can save the results to output files. The generated `cache.data` file can be used by the DNS-server-test program.
## Usage
```sh
Commands:
  Required parameters:
    -f  "/test.txt"   Domains file path
    -d  "x.x.x.x:xx"  DNS address
    -r  "xxx"         Request per second
  Optional parameters:
    -b  "/test.txt"   Subnets not add to the routing table
    --save            Save DNS answer data to cache.data,
                      DNS answer domains to out_domains.txt,
                      DNS answer IPs to ips.txt
```
