#!/usr/bin/env python3
import dns.query
import dns.message
import dns.name
import dns.rdatatype
import dns.rdtypes.svcbbase

qname = dns.name.from_text('crypto.cloudflare.com.')
request = dns.message.make_query(qname, dns.rdatatype.HTTPS)
response = dns.query.https(request, '1.1.1.1')
params=[x for x in response.answer[0].items.keys()][0].params
print(params.get(dns.rdtypes.svcbbase.ParamKey.IPV4HINT).to_text())
print(params.get(dns.rdtypes.svcbbase.ParamKey.IPV6HINT).to_text())
print(params.get(dns.rdtypes.svcbbase.ParamKey.ECH).to_text())