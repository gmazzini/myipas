<?php
echo "<pre>";
echo "On the basis of RIPE RIS data sets https://www.ris.ripe.net/\n";
echo "List of data collectors https://ris.ripe.net/docs/route-collectors\n";
echo "Real time collection from RRC00 Amsterdam\n";
echo "data is hourly updated\n";
echo "retention is 10 days\n";

function oo($txt,$ff){
  $m=(int)exec("wc -l /home/www/fulltable/$ff");
  echo "<a href='$ff'>Collected Routing Table $txt, $m raws</a>\n";
}
oo("IPv4","m4.txt");
oo("IPv6","m6.txt");

?>
