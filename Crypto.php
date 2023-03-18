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
        $len = strlen($data);
        if ($len > 1410) {
            return;
        }
        if ($len < 940) {
            $data1 = substr($data, 0, 470);
            $data2 = substr($data, 470);
            openssl_public_encrypt($data1, $encrypted_data1, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_public_encrypt($data2, $encrypted_data2, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            return base64_encode($encrypted_data1 . $encrypted_data2);
        } elseif ($len > 940) {
            $data1 = substr($data, 0, 470);
            $data2 = substr($data, 470, 470);
            $data3 = substr($data, 940, 470);
            openssl_public_encrypt($data1, $encrypted_data1, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_public_encrypt($data2, $encrypted_data2, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_public_encrypt($data3, $encrypted_data3, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            return base64_encode($encrypted_data1 . $encrypted_data2 . $encrypted_data3);
        } else {
            openssl_public_encrypt($data, $encrypted_data, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
            return base64_encode($encrypted_data);
        }
    }

    public static function asymmetricDecryptPrivate($data, $privateKey)
    {
        $len = strlen($data);
        $data = base64_decode($data);
        if ($len == 684) {
            $data1 = substr($data, 0, 512);
            $data2 = substr($data, 512);
            openssl_private_decrypt($data1, $decrypted_data1, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_private_decrypt($data2, $decrypted_data2, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            return $decrypted_data1 . $decrypted_data2;
        } elseif ($len == 1368) {
            $data1 = substr($data, 0, 512);
            $data2 = substr($data, 512, 512);
            $data3 = substr($data, 1024, 344);
            openssl_private_decrypt($data1, $decrypted_data1, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_private_decrypt($data2, $decrypted_data2, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_private_decrypt($data3, $decrypted_data3, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            return $decrypted_data1 . $decrypted_data2 . $decrypted_data3;
        } elseif ($len == 2048) {
            $data1 = substr($data, 0, 512);
            $data2 = substr($data, 512, 512);
            $data3 = substr($data, 1024, 512);
            $data4 = substr($data, 1536, 512);
            openssl_private_decrypt($data1, $decrypted_data1, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_private_decrypt($data2, $decrypted_data2, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_private_decrypt($data3, $decrypted_data3, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            openssl_private_decrypt($data4, $decrypted_data4, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            return $decrypted_data1 . $decrypted_data2 . $decrypted_data3 . $decrypted_data4;
        }
    }

    public static function asymmetricEncryptPrivate($data, $privateKey)
    {
        $len = strlen($data);
        if ($len > 2048) {
            return;
        }
        if ($len <= 684) {
            $data1 = substr($data, 0, 500);
            $data2 = substr($data, 500, 184);
            openssl_private_encrypt($data1, $encrypted_data1, $privateKey);
            openssl_private_encrypt($data2, $encrypted_data2, $privateKey);
            return base64_encode($encrypted_data1 . $encrypted_data2);
        } elseif ($len == 1368) {
            $data1 = substr($data, 0, 500);
            $data2 = substr($data, 500, 500);
            $data3 = substr($data, 1000, 368);
            openssl_private_encrypt($data1, $encrypted_data1, $privateKey);
            openssl_private_encrypt($data2, $encrypted_data2, $privateKey);
            openssl_private_encrypt($data3, $encrypted_data3, $privateKey);
            return base64_encode($encrypted_data1 . $encrypted_data2 . $encrypted_data3);
        } elseif ($len == 2048) {
            $data1 = substr($data, 0, 500);
            $data2 = substr($data, 500, 500);
            $data3 = substr($data, 1000, 500);
            $data4 = substr($data, 1500, 500);
            $data5 = substr($data, 2000, 48);
            openssl_private_encrypt($data1, $encrypted_data1, $privateKey);
            openssl_private_encrypt($data2, $encrypted_data2, $privateKey);
            openssl_private_encrypt($data3, $encrypted_data3, $privateKey);
            openssl_private_encrypt($data4, $encrypted_data4, $privateKey);
            openssl_private_encrypt($data5, $encrypted_data5, $privateKey);
            return base64_encode($encrypted_data1 . $encrypted_data2 . $encrypted_data3 . $encrypted_data4 . $encrypted_data5);
        } else {
            return false;
        }
    }

    public static function asymmetricDecryptPublic($data, $publicKey): bool|string
    {
        $len = strlen($data);
        $data = base64_decode($data);
        if ($len > 3416) {
            return false;
        }
        if ($len == 1368) {
            $data1 = substr($data, 0, 512);
            $data2 = substr($data, 512, 512);
            $data3 = substr($data, 1024, 344);
            openssl_public_decrypt($data1, $encrypted_data1, $publicKey);
            openssl_public_decrypt($data2, $encrypted_data2, $publicKey);
            openssl_public_decrypt($data3, $encrypted_data3, $publicKey);
            return $encrypted_data1 . $encrypted_data2 . $encrypted_data3;
        } elseif ($len == 2048) {
            $data1 = substr($data, 0, 512);
            $data2 = substr($data, 512, 512);
            $data3 = substr($data, 1024, 512);
            $data4 = substr($data, 1536, 512);
            openssl_public_decrypt($data1, $encrypted_data1, $publicKey);
            openssl_public_decrypt($data2, $encrypted_data2, $publicKey);
            openssl_public_decrypt($data3, $encrypted_data3, $publicKey);
            openssl_public_decrypt($data4, $encrypted_data4, $publicKey);
            return $encrypted_data1 . $encrypted_data2 . $encrypted_data3 . $encrypted_data4;
        } elseif ($len == 3416) {
            $data1 = substr($data, 0, 512);
            $data2 = substr($data, 512, 512);
            $data3 = substr($data, 1024, 512);
            $data4 = substr($data, 1536, 512);
            $data5 = substr($data, 2048, 512);
            $data6 = substr($data, 2560, 512);
            $data7 = substr($data, 3072, 344);
            openssl_public_decrypt($data1, $encrypted_data1, $publicKey);
            openssl_public_decrypt($data2, $encrypted_data2, $publicKey);
            openssl_public_decrypt($data3, $encrypted_data3, $publicKey);
            openssl_public_decrypt($data4, $encrypted_data4, $publicKey);
            openssl_public_decrypt($data5, $encrypted_data5, $publicKey);
            openssl_public_decrypt($data6, $encrypted_data6, $publicKey);
            openssl_public_decrypt($data7, $encrypted_data7, $publicKey);
            return $encrypted_data1 . $encrypted_data2 . $encrypted_data3 . $encrypted_data4 . $encrypted_data5 . $encrypted_data6 . $encrypted_data7;
        } else {
            return false;
        }
    }

    public function __call(string $name, array $arguments)
    {
        $instance = new self();
        call_user_func_array([$instance, $name], $arguments);
    }
}
