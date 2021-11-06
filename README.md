# gfwlist-ipset

```
 ./update.py -h
usage: update.py [-h] [--verbose] [--dns DNS] [--ipset IPSET]
                 [--output OUTPUT] [--extra EXTRA]

Simple gfwlist ipset updater, version 0.1

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Show verbose messages
  --dns DNS, -d DNS     dns ip
  --ipset IPSET, -i IPSET
                        ipset list name
  --output OUTPUT, -o OUTPUT
                        output file
  --extra EXTRA, -e EXTRA
                        extra domain names


```
Update the list

```
./update.py -e gfwlist.ext
2021-11-06 11:20:13,760 Updater: INFO [_update_gfw_list/100] total domain 6059
```
