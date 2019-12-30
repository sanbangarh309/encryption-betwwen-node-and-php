<?php
ini_set('display_errors', 1);
define('AES_METHOD', 'aes-256-cbc');
$data = new \stdClass();
$data->phone='9896747812';$data->countryCode='+966';$data->password='123456';$data->deviceType='web';
$data->deviceToken='232323232323';
$password = 'lbwyBzfgzUIvXZFShJuikaWvLJhIVq36';
$encrypted = encrypt($data, $password);
echo $encrypted; echo "<pre>";
$decrypted = decrypt($encrypted,$password);
print_r(json_decode($decrypted)); echo "<pre>";
function encrypt($message, $password)
{
    if (OPENSSL_VERSION_NUMBER <= 268443727) {
        throw new RuntimeException('OpenSSL Version too old, vulnerability to Heartbleed');
    }
    
    $iv_size        = openssl_cipher_iv_length(AES_METHOD);
    $iv             = openssl_random_pseudo_bytes($iv_size);
    $ciphertext     = openssl_encrypt(json_encode($message), AES_METHOD, $password, OPENSSL_RAW_DATA, $iv);
    $ciphertext_hex = bin2hex($ciphertext);
    $iv_hex         = bin2hex($iv);
    return "$iv_hex:$ciphertext_hex";
}
function decrypt($ciphered, $password)
{
    $iv_size    = openssl_cipher_iv_length(AES_METHOD);
    $data       = explode(":", $ciphered);
    $iv         = hex2bin($data[0]);
    $ciphertext = hex2bin($data[1]);
    return openssl_decrypt($ciphertext, AES_METHOD, $password, OPENSSL_RAW_DATA, $iv);
}
?>