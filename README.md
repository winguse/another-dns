# Another DNS

Basically, it's another implementation of [Green DNS](https://github.com/faicker/greendns). Written in golang to make it possible to be running in router easier.

A little update for the logic:

1. query the `-vpn-dns` with the requested domain name twice:
   1. query with eDNS source IP (default to an address Beijing)
   2. query without eDNS source IP
2. if the eDNS source IP request returned an address within `cn-range`, then query the request with `local-dns`
      if `local-dns` is not defined, query with `vpn-dns` with eDNS settings.
   else query `vpn-dns`

The application will cache the result of step one for 5 minutes. But it will not cache the DNS result because caching can be done by other good tools.

How to get CN CIDRs?

Run the following in the Chrome console:

```js
async function getCN() {
  const response = await fetch('https://ftp.apnic.net/stats/apnic/delegated-apnic-latest')
  const text = await response.text();
  const content = text.split('\n')
    .map(l => l.trim())
    .filter(l => !l.startsWith('#'))
    .map(l => l.split('|'))
    .map(([, country, type, addr, count]) => ({
      country, type, addr, count,
    }))
    .filter(({country, type}) => country === 'CN' && type === 'ipv4')
    .map(({addr, count}) => `${addr}/${Math.floor(32 - Math.log2(count))}`)
    .join('\n')
  return content
}

getCN().then(console.log)
```
