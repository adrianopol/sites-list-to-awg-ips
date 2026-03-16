# Domain to IP Address List Converter

AmneziaWG is an improved version of the WireGuard protocol, commonly used by AmneziaVPN clients. However, the AmneziaVPN UI is limited when you need to frequently adjust your network traffic routing. This tool converts a plain-text file of domains into a JSON IP address list that can be imported into the AmneziaVPN client for site-based split tunneling.

## TL;DR

- `echo -e "example.org www.example.org\nexample.net" > my-sites.lst`
- `make` (see also the Recommendations section)
- in the [AmneziaVPN client](https://github.com/amnezia-vpn/amnezia-client):
  - disconnect from the VPN
  - go to _Split tunneling enabled/disabled_ -> _Site-based split tunneling_
  - press ⋮ in the bottom right corner
  - go to _Import_ -> _Replace site list_
  - select the generated JSON file (named like `my-sites-2026-01-02_11.22.33.json`)

## Why?

The AmneziaVPN interface is inconvenient for adding, removing, and updating endpoints used for site-based split tunneling. This tool improves several aspects:

- **(Nearly) complete domain name resolution**: When you save a domain name in the client, it is sometimes resolved to a single IP address, ignoring possible load balancers that implement Round Robin or other rotation methods. This causes frequent VPN tunnel misses. This tool performs multiple consecutive lookups to capture all IP addresses.
- **Organize endpoints into sets and document them with comments**: You can easily enable/disable a partucular resource by commenting out several lines containing domains and/or IP addresses.
- **IaC support**: The domain list is a plain-text file that can be stored in a VCS.

## Input file syntax example

```
# this is a comment: all text between '#' and end of line is ignored

site1.com
site2.com www.site2.com cnd1-for-site.org # this is an inline comment

# this is a comment also; empty lines are also ignored
site3.org
```

## Requirements

- Go language compiler (`go` command)

## Recommendations

- Before running the binary (`make` command in the example above) turn off the VPN.
