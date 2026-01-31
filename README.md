# DNS client test
DNS-client-test program resolves domains from a file with a set number of requests per second. And it can save the results to files. The cache.data can be used in the dns-server-test program.
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
