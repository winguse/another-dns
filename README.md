# Another DNS

Basically, it's another implementation of [Green DNS](https://github.com/faicker/greendns). Written in golang to make it possible to be running in router easier.

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
