<?php
echo "<pre>";
echo "On the basis of RIPE RIS data sets https://www.ris.ripe.net/\n";
echo "List of data collectors https://ris.ripe.net/docs/route-collectors\n";
echo "Real time collection\n";
echo "Data is hourly published\n";
echo "Retention is 30 days\n";
echo "Real time query in IPv4 and IPv6 is open with whois, e.g. whois -h ipas.mazzini.org 1.1.1.1\n\n";

function oo($txt,$ff){
  $m=(int)exec("wc -l /home/www/fulltable/$ff");
  echo "<a href='$ff'>Collected Routing Table $txt, $m raws</a>\n";
}
oo("IPv4","m4.txt");
oo("IPv6","m6.txt");

?>
