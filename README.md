# Skanuvaty

Dangerously fast dns/network/port scanner, all-in-one. 

![Demonstration](./demo.gif)

Start with a domain, and we'll find everything about it.

Features:

- Finds subdomains from root domain
- Finds IPs for subdomains
- Checks what ports are open on those IPs (Notice: not yet implemented)

Outputs a handy .json file with all the data for further investigation.

Runs as fast as your computer/network/DNS resolver allows it to be. Test run for 10.000 subdomains
tested all of them in ~20 seconds with `concurrency` set to 16 on a machine with 16 (logical) cores.

## Usage

```shell
skanuvaty --target nmap.org --concurrency 16 --subdomains-file /usr/share/dnsenum/dns.txt
```

The terminal will show all found subdomains + a `skanuvaty.scan.json` file has been created in your current directory.

## License

MIT 2021
