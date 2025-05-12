<pre>
written by Gianluca Mazzini gianluca@mazzini.org started in 2015
ip to as resolution with dns query
command may be given by usung a dns query with TXT mode
example dig -p 5555 @ipas.mazzini.org +short -t TXT cmd/ipas/64.52.4.0/

list of commands
cmd/reload/ for runtime ip to as configuration reloading
cmd/ipas/\<ipv4\>/ to obtain the as for such an ipv4
cmd/status/ to obtain a short status of query
cmd/reset/ to reset the status counters

file is composed by rows with three elements, space separated: IP/CIDR,ASN
file is collected on http://fulltable.mazzini.org
</pre>
