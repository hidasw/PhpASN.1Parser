<pre>
<?php
//============================================================+
// File name   : hda_asn1Parser.php
// Version     : 1.0.1
// Begin       : 26/03/2009
// Last Update : 20/05/2023
// Author      : Hida - https://github.com/hidasw
// License     : GPL-3.0 license
// -------------------------------------------------------------------
// Copyright (C) 2009-2023 Hida
//
//
// Description :
//   This is a PHP function hda_asn1parse_recursive is for parsing hex form asn.1 to Array recursively with specified depth.



// unrecursive function
function hda_asn1parse($hex) {
	  if(!@ctype_xdigit($hex) || @strlen($hex)%2!=0) {
		  return false;
	  }
	  $stop = false;
	  while($stop == false) {
      $asn1_type = substr($hex, 0, 2);
      $tlv_tagLength = hexdec(substr($hex, 2, 2));
      if($tlv_tagLength > 127) {
        $tlv_lengthLength = $tlv_tagLength-128;
        $tlv_valueLength = substr($hex, 4, ($tlv_lengthLength*2));
      } else {
        $tlv_lengthLength = 0;
        $tlv_valueLength = substr($hex, 2, 2+($tlv_lengthLength*2));
      }
      if($tlv_lengthLength >4) { // limit tlv_lengthLength to FFFF
        return false;
      }
      //if($tlv_valueLength > intval(str_repeat('9',14))) { // limit to 99.999.999.999.999
        //return false;
      //}
      $tlv_valueLength = hexdec($tlv_valueLength);
      
      $totalTlLength = 2+2+($tlv_lengthLength*2);
      $reduction = 2+2+($tlv_lengthLength*2)+($tlv_valueLength*2);
      $tlv_value = substr($hex, $totalTlLength, $tlv_valueLength*2);
      $remain = substr($hex, $totalTlLength+($tlv_valueLength*2));
      $newhexdump = substr($hex, 0, $totalTlLength+($tlv_valueLength*2));
      
      $result[] = array(
                        //'tlv_tagLength'=>strlen(dechex($tlv_tagLength))%2==0?dechex($tlv_tagLength):'0'.dechex($tlv_tagLength),
                        //'tlv_lengthLength'=>$tlv_lengthLength,
                        'tlv_valueLength'=>$tlv_valueLength,
                        //'reduction'=>$reduction,
                        //'hex'=>$hex,
                        'newhexdump'=>$newhexdump,
                        'typ'=>$asn1_type,
                        'tlv_value'=>$tlv_value
                        //'remain'=>$remain
                        );

      //if($remain == '' && $tlv_value == '' && $asn1_type != '05') { // if remains string was empty & contents also empty, function return FALSE
      if($remain == '') { // if remains string was empty & contents also empty, function return FALSE
        $stop = true;
      } else {
        $hex = $remain;
      }
	  }
	  return $result;
}



// Main function
function hda_asn1parse_recursive($hex, $maxDepth=5) {
  $result = array();
  $asn1parse_array = hda_asn1parse($hex);
  static $currentDepth = 0;
  if($asn1parse_array) {
    foreach($asn1parse_array as $ff){
      $k = $ff['typ'];
      $v = $ff['tlv_value'];
      $info['depth']=$currentDepth;
      $info['hexdump']=$ff['newhexdump'];
      $info['type'] = $k;  
      $info['value_hex'] = $v;  
      if(($currentDepth <= $maxDepth)) {
        if($info['type'] == '06') {

        } else if($info['type'] == '13' ||
                   $info['type'] == '18'
                   ) {
          $info['value'] = hex2bin($info['value_hex']);
        } else if(
                   $info['type'] == '03' ||
                   $info['type'] == '02'
                   ) {
          $info['value'] = $info['value_hex'];
        } else if(
                   $info['type'] == '05'
                   ) {

        } else {
          $currentDepth++;
          $info['value'] = hda_asn1parse_recursive($v, $maxDepth); 
          $currentDepth--;
        }
        $result[] = $info;
      }
    }
  } else {
    //unset($info['value']);
    $result = false;
  }
  return $result;
}

?>