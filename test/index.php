<pre>
<?php
ob_start(); // just for print line number on left side page


require('../asn1.php');

// Parse asn.1 (x509 binary/der certificate)
$derfile = file_get_contents('Local Root CA.cer');
// Conver to hex
$hexform = bin2hex($derfile);
// Parsing with depth 5
$result = asn1::parse($hexform,5);
// View result
print_r($result);


// just for print line number on left side page
$out = ob_get_contents();
ob_end_clean();
$ar = explode("\n", $out);
$vis = '';
$i=count($ar);
$iLength=strlen($i);
foreach($ar as $arv) {
  $vis .= '<span style="background-color:grey"><b>'.str_pad($i, $iLength, " ")."</b></span> $arv\n";
  $i--;
}
echo $vis;
?>