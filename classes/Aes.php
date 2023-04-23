<?php
class Aes
{
    
 private $key;
 private $iv;
 private $method;
 public function __construct() {
 $this->key=hash('sha256', "sd3fW\$feW#7\$TFAWE$", true);
 $this->iv="dlD4%6R6Rfdl405d";
 $this->method = "AES-256-CBC";
 }
 function encrypt($plaintext) {
 return openssl_encrypt($plaintext, $this->method, $this->key,
OPENSSL_RAW_DATA, $this->iv);
 }
 function decrypt($ciphertext) {
 return openssl_decrypt($ciphertext, $this->method,
$this->key, OPENSSL_RAW_DATA, $this->iv);
 }
}