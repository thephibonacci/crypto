<?php

namespace System\crypto;

use System\config\Config;

class Crypto
{

    public static function encryptAES($str, $key = "33961273497831517403165593056186288890788015773647", $hex = true): string
    {
        $res = base64_encode(openssl_encrypt($str, "AES-256-CBC", hash('sha512', $key), 0, substr(hash("sha256", $key), 0, 16)));
        return $hex ? bin2hex($res) : $res;
    }

    public static function decryptAES($str, $key = "33961273497831517403165593056186288890788015773647", $hex = true): string
    {
        return openssl_decrypt(base64_decode($hex ? hex2bin($str) : $str), "AES-256-CBC", hash('sha512', $key), 0, substr(hash("sha256", $key), 0, 16));
    }

    public static function encryptAES192($str, $key = "33961273497831517403165593056186288890788015773647", $hex = true): string
    {
        $res = base64_encode(openssl_encrypt($str, "AES-192-CBC", hash('sha512', $key), 0, substr(hash("sha256", $key), 0, 16)));
        return $hex ? bin2hex($res) : $res;
    }

    public static function decryptAES192($str, $key = "33961273497831517403165593056186288890788015773647", $hex = true): string
    {
        return openssl_decrypt(base64_decode($hex ? hex2bin($str) : $str), "AES-192-CBC", hash('sha512', $key), 0, substr(hash("sha256", $key), 0, 16));
    }

    public static function encryptAES128($str, $key = "33961273497831517403165593056186288890788015773647", $hex = true): string
    {
        $res = base64_encode(openssl_encrypt($str, "AES-128-CBC", hash('sha512', $key), 0, substr(hash("sha256", $key), 0, 16)));
        return $hex ? bin2hex($res) : $res;
    }

    public static function decryptAES128($str, $key = "33961273497831517403165593056186288890788015773647", $hex = true): string
    {
        return openssl_decrypt(base64_decode($hex ? hex2bin($str) : $str), "AES-128-CBC", hash('sha512', $key), 0, substr(hash("sha256", $key), 0, 16));
    }

    public static function generateAsymmetricKey($private_key_bits = 4096): array
    {
        $opt = array('private_key_bits' => $private_key_bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'default_md' => "sha512");
        $private_key = openssl_pkey_new($opt);
        $pubKey = openssl_pkey_get_details($private_key)['key'];
        openssl_pkey_get_public($pubKey);
        $privKey = openssl_pkey_get_private($private_key);
        openssl_pkey_export($privKey, $priKey);
        return array("pubKey" => $pubKey, "privKey" => $priKey);
    }    

    public static function asymmetricEncryptPublic($data, $publicKey)
    {
        if(strlen($data) > 214)
        {            
            openssl_public_encrypt(substr($data, 0, 214), $encrypted_data, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            $encrypted_data .= self::asymmetricEncryptPublic(substr($data, 214), $publicKey);            
        }
        else {
            openssl_public_encrypt($data, $encrypted_data, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
        }
        return base64_encode($encrypted_data);
    }

    public static function asymmetricDecryptPublic($data, $publicKey): bool|string
    {
        if (base64_decode($data, true) === true) { $data = base64_decode($data); }

        if(strlen($data) > 512)
        {            
            openssl_public_decrypt(substr($data, 0, 512), $decrypted_data, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            $decrypted_data .= self::asymmetricDecryptPublic(substr($data, 512), $publicKey);            
        }
        else {            
            openssl_public_decrypt($data, $decrypted_data, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
        }
        return $decrypted_data;
    }

    public static function asymmetricEncryptPrivate($data, $privateKey)
    {
        if(strlen($data) > 214)
        {            
            openssl_private_encrypt(substr($data, 0, 214), $encrypted_data, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            $encrypted_data .= self::asymmetricEncryptPrivate(substr($data, 214), $privateKey);
        }
        else {
            openssl_private_encrypt($data, $encrypted_data, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);            
        }
        return base64_encode($encrypted_data);
    }

    public static function asymmetricDecryptPrivate($data, $privateKey)
    {
        if (base64_decode($data, true) === true) { $data = base64_decode($data); }

        if(strlen($data) > 512)
        {            
            openssl_private_decrypt(substr($data, 0, 512), $decrypted_data, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            $decrypted_data .= self::asymmetricDecryptPrivate(substr($data, 512), $privateKey);            
        }
        else {            
            openssl_private_decrypt($data, $decrypted_data, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
        }
        return $decrypted_data;
    }

    public function __call(string $name, array $arguments)
    {
        $instance = new self();
        call_user_func_array([$instance, $name], $arguments);
    }
}
