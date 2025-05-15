<?php
echo "<pre>On the basis of RIPE RIS data sets https://www.ris.ripe.net/\n";
echo "Real time collection from RRC00 Amsterdam\n";
echo "now version is hourly updated\n";
echo "Rotation occurs in the night\n\n";

function oo($txt,$ff){
  $m=(int)exec("wc -l /home/www/fulltable/$ff");
  echo "<a href='$ff'>Collected Routing Table $txt, $m raws</a>\n";
}
oo("IPv4 now","m4.txt");
oo("IPv6 now","m6.txt");
oo("IPv4 1d ago","m4-1.txt");
oo("IPv6 1d ago","m6-1.txt");
oo("IPv4 2d ago","m4-2.txt");
oo("IPv6 2d ago","m6-2.txt");
oo("IPv4 3d ago","m4-3.txt");
oo("IPv6 3d ago","m6-3.txt");
oo("IPv4 4d ago","m4-4.txt");
oo("IPv6 4d ago","m6-4.txt");
oo("IPv4 5d ago","m4-5.txt");
oo("IPv6 5d ago","m6-5.txt");

?>
