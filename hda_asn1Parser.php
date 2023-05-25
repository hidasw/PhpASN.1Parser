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



	/**
	 * parse asn.1 to array
	 * to be called from $this->parse_recursive() function
	 * @param string $hex asn.1 hex form
	 * @return array asn.1 structure
	 * @protected
	 */
function hda_asn1parse($hex) {
	if(!@ctype_xdigit($hex) || @strlen($hex)%2!=0) {
		$this->errorMsg = "input not hex string!.";
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
		$tlv_valueLength = hexdec($tlv_valueLength);
		
		$totalTlLength = 2+2+($tlv_lengthLength*2);
		$reduction = 2+2+($tlv_lengthLength*2)+($tlv_valueLength*2);
		$tlv_value = substr($hex, $totalTlLength, $tlv_valueLength*2);
		$remain = substr($hex, $totalTlLength+($tlv_valueLength*2));
		$newhexdump = substr($hex, 0, $totalTlLength+($tlv_valueLength*2));
		
		$result[] = array(
						'tlv_tagLength'=>strlen(dechex($tlv_tagLength))%2==0?dechex($tlv_tagLength):'0'.dechex($tlv_tagLength),
						'tlv_lengthLength'=>$tlv_lengthLength,
						'tlv_valueLength'=>$tlv_valueLength,
						'newhexdump'=>$newhexdump,
						'typ'=>$asn1_type,
						'tlv_value'=>$tlv_value
						);

		if($remain == '') { // if remains string was empty & contents also empty, function return FALSE
			$stop = true;
		} else {
			$hex = $remain;
		}
	}
	return $result;
}



	/**
	 * parse asn.1 to array recursively
	 * @param string $hex asn.1 hex form
	 * @param int $maxDepth maximum parsing depth
	 * @return array asn.1 structure recursively to specific depth
	 * @public
	 */
function hda_asn1parse_recursive($hex, $maxDepth=5) {
	$result = array();
	$info = array();
	$parse_recursive = array();
	$asn1parse_array = $this->parse($hex);
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
				if($k == '06') {

				} else if($k == '13' || $k == '18') {
					$info['value'] = hex2bin($info['value_hex']);
				} else if($k == '03' || $k == '02') {
					$info['value'] = $v;
				} else if($k == '05') {

				} else {
					$currentDepth++;
					$parse_recursive = $this->parse_recursive($v, $maxDepth); 
					$currentDepth--;
				}
				if($parse_recursive) {
					$result[] = array_merge($info, $parse_recursive);
				} else {
					$result[] = $info;
				}
				unset($info['value']);
			}
		}
	} else {
		$result = false;
	}
	return $result;
}

?>