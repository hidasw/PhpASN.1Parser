# Php ASN.1
Independent Asn.1 Parse & Create
## Description
Php function to parse and create ASN.1 hex form.<br>
base64 form need to decoded then convert to hex.<br>
DER form need to convert to hex.<br>
## Usage
### Parse as array:
Parse hex encoded and return as array:
```php
include 'asn1.php;
// $hex is hex form such from bin2hex()
$return = asn1::parse($hex);
```
To specify max parsing depth:
```php
$maxdepth = 9;
asn1::parse($hex, $maxdepth);
```
### Create:
create sequence:
```php
asn1::sequence($hexdata);
```
create set:
```php
asn1::set($hexdata);
```
create various structure:
```php
asn1::sequence(
              asn::sequence(
                            asn1::integer('2')
                            ).
              asn1::set(
                        asn1::bitstr('00')
                        )
              );

```
## Supported tags
```php
asn1::sequence($hex);
asn1::octet($hex);
asn1::object($hex);
asn1::bitstr($hex);
asn1::printablestr($str);
asn1::integer($int);
asn1::set($hex);
asn1::explicit($explicitNumber, $hex);
asn1::implicit($num="0");
asn1::utctime($time); // ymdHis
asn1::generalizedtime($time); // YmdHis
asn1::utf8str($str);
asn1::ia5str($str);
asn1::visiblestr($str);
asn1::t61str($str);
```
