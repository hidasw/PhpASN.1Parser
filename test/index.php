<pre>
<?php
ob_start(); // just for print line number on left side page


require('../asn1.php');

// Create ASN.1 Form
$asn1Hex = asn1::sequence(
							asn1::generalizedtime('20230102121314').
							asn1::printablestr('Hello world.')
							);
$asn1Der = hex2bin($asn1Hex); // can be read by openssl asn1parse -i -inform der
$asn1Base64 = chunk_split(base64_encode($asn1Der), 65); // can be read by openssl asn1parse -i
echo "ASN.1 Hex Form :".$asn1Hex."\n";
echo "ASN.1 Base64   :".$asn1Base64."\n";

// Parse asn.1 (x509 binary/der certificate)
$derfile = file_get_contents('Local Root CA.cer');
// Conver to hex
$hexform = bin2hex($derfile);
// Parsing with depth 9
$result = asn1::parse($hexform,9);
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