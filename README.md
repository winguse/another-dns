# Another DNS

In some countries in the world, your [DNS will be polluted](https://en.wikipedia.org/wiki/DNS_spoofing).

There is a country, when your DNS request go through their firewall (both sides of the firewall) and they decide to pollute against your request, they will return two DNS responses in advance.

To ensure your privacy, it's better to send your probe traffic inside VPN, for example, you can use iptables to setup a redir port that will route the DNS request inside the firewall.

```
#!/bin/sh

local_ip=YOUR_INTERFACE_IP
probe_addr=203.208.0.0
iptables -t nat -I PREROUTING -p udp -m udp --dport 8053 -j DNAT --to-destination $probe_addr:53
iptables -t nat -I POSTROUTING -d $probe_addr -p udp -m udp --dport 53 -j SNAT --to-source $local_ip

```

