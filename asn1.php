<?php
//============================================================+
// File name   : hda_asn1Parser.php
// Version     : 1.0.1
// Begin       : 26/03/2009
// Last Update : 02/06/2023
// Author      : Hida - https://github.com/hidasw
// License     : GPL-3.0 license
// -------------------------------------------------------------------
// Copyright (C) 2009-2023 Hida
//
//
// Description :
//   Parsing asn.1 hex form to Array recursively with specified depth.


class asn1 {
	// =====Begin ASN.1 Parser section=====
	/**
	 * get asn.1 type tag name
	 * @param string $id hex asn.1 type tag
	 * @return string asn.1 tag name
	 * @protected
	 */
	protected static function type($id) {
		$asn1_Types = array(
		"00" => "ASN1_EOC",
		"01" => "ASN1_BOOLEAN",
		"02" => "ASN1_INTEGER",
		"03" => "ASN1_BIT_STRING",
		"04" => "ASN1_OCTET_STRING",
		"05" => "ASN1_NULL",
		"06" => "ASN1_OBJECT",
		"07" => "ASN1_OBJECT_DESCRIPTOR",
		"08" => "ASN1_EXTERNAL",
		"09" => "ASN1_REAL",
		"0a" => "ASN1_ENUMERATED",
		"0c" => "ASN1_UTF8STRING",
		"30" => "ASN1_SEQUENCE",
		"31" => "ASN1_SET",
		"12" => "ASN1_NUMERICSTRING",
		"13" => "ASN1_PRINTABLESTRING",
		"14" => "ASN1_T61STRING",
		"15" => "ASN1_VIDEOTEXSTRING",
		"16" => "ASN1_IA5STRING",
		"17" => "ASN1_UTCTIME",
		"18" => "ASN1_GENERALIZEDTIME",
		"19" => "ASN1_GRAPHICSTRING",
		"1a" => "ASN1_VISIBLESTRING",
		"1b" => "ASN1_GENERALSTRING",
		"1c" => "ASN1_UNIVERSALSTRING",
		"1d" => "ASN1_BMPSTRING"
		);
		return array_key_exists($id,$asn1_Types)?$asn1_Types[$id]:$id;
	}

	/**
	 * parse asn.1 to array
	 * to be called from parse() function
	 * @param string $hex asn.1 hex form
	 * @return array asn.1 structure
	 * @protected
	 */
	protected static function oneParse($hex) {
		if(!@ctype_xdigit($hex) || @strlen($hex)%2!=0) {
			echo "input:\"$hex\" not hex string!.\n";
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
	public static function parse($hex, $maxDepth=5) {
		$result = array();
		static $currentDepth = 0;
		if($asn1parse_array = self::oneParse($hex)) {
			foreach($asn1parse_array as $ff){
				$parse_recursive = false;
				unset($info);
				$k = $ff['typ'];
				$v = $ff['tlv_value'];
				$info['depth']=$currentDepth;
				$info['hexdump']=$ff['newhexdump'];
				$info['type'] = $k;  
				$info['typeName'] = self::type($k);  
				$info['value_hex'] = $v;  
				if(($currentDepth <= $maxDepth)) {
					if($k == '06') {
						
					} else if($k == '13' || $k == '18') {
						$info['value'] = hex2bin($info['value_hex']);
					} else if($k == '03' || $k == '02' || $k == 'a04') {
						$info['value'] = $v;
					} else if($k == '05') {
						
					} else if($k == '01') {

					} else {
						$currentDepth++;
						$parse_recursive = self::parse($v, $maxDepth);
						$currentDepth--;
					}
					if($parse_recursive) {
						$result[] = array_merge($info, $parse_recursive);
					} else {
						$result[] = $info;
					}
				}
			}
		}
		return $result;
	}
	// =====End ASN.1 Parser section=====

	// =====Begin ASN.1 Builder section=====
	/**
	 * create asn.1 TLV tag length, length length and value length
	 * to be called from asn.1 builder functions
	 * @param string $str string value of asn.1
	 * @return string hex of asn.1 TLV tag length
	 * @protected
	 */
	protected static function asn1_header($str) {
		$len = strlen($str)/2;
		$ret = dechex($len);
		if(strlen($ret)%2 != 0) {
			$ret = "0$ret";
		}

		$headerLength = strlen($ret)/2;
		if($len > 127) {
			$ret = "8".$headerLength.$ret;
		}
		return $ret;
	}

	/**
	 * Create asn.1 SEQUENCE
	 * @param string $hex hex value of asn.1 SEQUENCE
	 * @return tring hex of asn.1 SEQUENCE tag with value
	 * @public
	 */
	public static function SEQUENCE($hex) {
		$ret = "30".self::asn1_header($hex).$hex;
		return $ret;
	}

	/**
	 * Create asn.1 OCTET
	 * @param string $hex hex value of asn.1 OCTET
	 * @return string hex of asn.1 OCTET tag with value
	 * @public
	 */
	public static function OCTET($hex)  {
		$ret = "04".self::asn1_header($hex).$hex;
		return $ret;
	}

	/**
	 * Create asn.1 OBJECT
	 * @param string $hex hex value of asn.1 OBJECT
	 * @return string hex of asn.1 OBJECT tag with value
	 * @public
	 */
	public static function OBJECT($hex)  {
		$ret = "06".self::asn1_header($hex).$hex;
		return $ret;
	}

	/**
	 * Create asn.1 BITString
	 * @param string $hex hex value of asn.1 BITString
	 * @return string hex of asn.1 BITString tag with value
	 * @public
	 */
	public static function BITSTR($hex)  {
		$ret = "03".self::asn1_header($hex).$hex;
		return $ret;
	}

	/**
	 * Create asn.1 PRINTABLEString tag
	 * @param string $str string value of asn.1 PRINTABLEString
	 * @return string hex of asn.1 PRINTABLEString tag with value
	 * @public
	 */
	public static function PRINTABLESTR($str)  {
		$ret = "13".self::asn1_header(str_repeat($str, 2)).bin2hex($str);
		return $ret;
	}

	/**
	 * Create asn.1 INTEGER
	 * @param string $int number value of asn.1 INTEGER
	 * @return string hex of asn.1 INTEGER tag with value
	 * @public
	 */
	public static function INTEGER($int)  {
		if(strlen($int)%2 != 0)  {
		$int = "0$int";
		}
		$int = "$int";
		$ret = "02".self::asn1_header($int).$int;
		return $ret;
	}

	/**
	 * Create asn.1 SET tag
	 * @param string $hex hex value of asn.1 SET
	 * @return string hex of asn.1 SET with value
	 * @public
	 */
	public static function SET($hex)  {
		$ret = "31".self::asn1_header($hex).$hex;
		return $ret;
	}

	/**
	 * Create asn.1 EXPLICIT
	 * @param string $num value of asn.1 EXPLICIT number
	 * @param string $hex value of asn.1 EXPLICIT
	 * @return string hex of asn.1 EXPLICIT with value
	 * @public
	 */
	public static function EXPLICIT($num, $hex)  {
		$ret = "a$num".self::asn1_header($hex).$hex;
		return $ret;
	}

	/**
	 * Create asn.1 IMPLICIT
	 * @param integer $num value of asn.1 IMPLICIT
	 * @return string hex of asn.1 IMPLICIT tag with value
	 * @public
	 */
	public static function IMPLICIT($num="0")  {
		if(strlen($num)%2 != 0)  {
		$num = "0$num";
		}
		$ret = "80$num";
		return $ret;
	}

	/**
	 * Create asn.1 UTCTIME
	 * @param string $time string value of asn.1 UTCTIME date("ymdHis")
	 * @return string hex of asn.1 UTCTIME tag with value
	 * @public
	 */
	public static function UTCTIME($time) {
		$ret = "170d".bin2hex($time)."5a";
		return $ret;
	}

	/**
	 * Create asn.1 GENERALIZEDTIME
	 * @param string $time string value of asn.1 GENERALIZEDTIME date("YmdHis")
	 * @return string hex of asn.1 GENERALIZEDTIME tag with value
	 * @public
	 */
	public static function GENERALIZEDTIME($time)  {
		$ret = "180f".bin2hex($time)."5a";
		return $ret;
	}

	/**
	 * Create asn.1 UTF8String
	 * @param string $str string value of asn.1 UTF8String
	 * @return string hex of asn.1 UTF8String tag with value
	 * @public
	 */
	public static function UTF8STR($str) {
		$ret = "0c".self::asn1_header(bin2hex($str)).bin2hex($str);
		return $ret;
	}

	/**
	 * Create asn.1 IA5String
	 * @param string $str string value of asn.1 IA5String
	 * @return string hex of asn.1 IA5String tag with value
	 * @public
	 */
	public static function IA5STR($str) {
		$ret = "16".self::asn1_header(bin2hex($str)).bin2hex($str);
		return $ret;
	}

	/**
	 * Create asn.1 VISIBLEString
	 * @param string $str string value of asn.1 VISIBLEString
	 * @return string hex of asn.1 VISIBLEString tag with value
	 * @public
	 */
	public static function VISIBLESTR($str) {
		$ret = "1a".self::asn1_header(bin2hex($str)).bin2hex($str);
		return $ret;
	}

	/**
	 * Create asn.1 T61String
	 * @param string $str string value of asn.1 T61String
	 * @return string hex of asn.1 T61String tag with value
	 * @public
	 */
	public static function T61STR($str) {
		$ret = "14".self::asn1_header(bin2hex($str)).bin2hex($str);
		return $ret;
	}

	/**
	 * Create asn.1 custom tag
	 * @param string hex value of asn.1 custom tag
	 * @return string hex of asn.1 custom tag with value
	 * @public
	 */
	public static function OTHER($id, $hex, $chr = false) {
		$str = $hex;
		if($chr != false) {
		$str = bin2hex($hex);
		}
		$ret = "$id".self::asn1_header($str).$str;
		return $ret;
	}
	// =====End ASN.1 Builder section=====
}
?>