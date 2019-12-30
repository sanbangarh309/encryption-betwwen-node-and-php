<?php
ini_set('display_errors', 1);
define('AES_METHOD', 'aes-256-cbc');
// $data = new \stdClass();
// print_r('$decryptedKey');exit;
// { encryptionData: '1b356cac83a5111082021a0bca51cb43:ddf53fc41bc2aaab1b734ea7f56afbd31cb73fc6bdfab20dc93bfa593726851c48bd88744c34d39bb8a97d5b7b6752ff4c4e6a93d63eb7b59b6091bea3880a67ff2d8815a976611f820acda79ae2803ee8cdf52f3c44773191c4808da210170ff4cdc90a6aad373f8622a697b4cdc9e8',
//   encryptionKey: 'ZBH6S72oxPeStRl33JykpC6AazjPtiRiPiPrW1tiaNxQAQG0lXJN3vWQBzJWVEPqZr6mbbqhwtTaL8yr9fT+PoL9F/cAIXrYP1QuYMluXUwodqz5Wj0h1drmmsNUEdAF9EfppXkM5AL8X79aBtTBMjEidi4ntKDi+po9Nyuw9dSVnfgDz4GM/DS2pn+VQipntClgIUt2iflPuKZ2xmVWRUE3a6aqSrftU0C3dSkPC7yWbcTn2YfvwnHiWAByXGLavYuPlvvrjurnx56AIIDmK5OlXYoSQ44KxKGYu0W8a+TSDhLQypwan33XBaOwPfCsgql71cPxoHLI0CLyWxKrJg==' }
// $data->phone='9896747812';$data->countryCode='+91';$data->password='123456';$data->deviceType='web';
// $data->deviceToken='232323232323';
$password = 'S4K7Vp5lpJVkpDIQRUQj1dDdNA3SGcMK8+UNWvfJAek=';
// $encrypted = encrypt($data, $password);
// echo $encrypted; echo "<pre>";
$decryptedKey = rsaDecrypt('TC0A8RhTdbmVzC01K0FRLfNqTkMs5fEOjzaJHcbwkPvJXWL62rxcEHw+Lb7HtGgoKu1cqs8SCLKU/1Dp9UoyRTx8sLD4SkkopWlMnOwYB2TE9K4cmw4eApDGstKzLzgDh1IW/W3y3aqagAfcwDFucneCLxBzCIBhtE6dHqqoL8IK8+IB/gHGE8YADA2EGg0ayPHjVIjLjvnaFq76AnVxPKaxmsHl+6q5VsX8YIJyBW7sblPLCd7OQbT9i9yb/qhaRRjwRZTuyKqwjyrYzcLT8HCSNLA3TeHzLZx51V3+MFs8iTVaZ5bnxS0IQkLg7phyORNjlbdlzj2oe5Asm1/hSA==');
// $decryptedKey = unpack("C*",base64_decode($decryptedKey));
echo "<pre>";print_r($decryptedKey);
$decrypted = decrypt('cb6b0e199bf81c62900a11f23b7bc9894a690d6a9ee055fd850cac57b3af0afff292ede301233b1b0d4a97b6076ac62d2992c5ed021835a109cde5f3d3684379aad51bb532f0e56aa973325e11f7fcc439f0fa44717a8ba75ed8fc42a179c346db7abb74b9f3761d529ed15e156ee803b751e5dc3ebe13d0b9af79ea680fa441c99a054aec4d10badbb91f6338e200da:5cdfe114f0c1e294ced04dbc18ce6775',$decryptedKey);
echo "<pre>";print_r(json_decode($decrypted)); echo "<pre>";
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
    return "$ciphertext_hex:$iv_hex";
}

function decrypt($ciphered, $password)
{
    $iv_size    = openssl_cipher_iv_length(AES_METHOD);
    $data       = explode(":", $ciphered);
    $iv         = hex2bin($data[1]);
    $ciphertext = hex2bin($data[0]);
    return openssl_decrypt($ciphertext, AES_METHOD, base64_decode($password), OPENSSL_RAW_DATA, $iv);
}

function rsaEncrypt($string){
    $publickey = @file_get_contents('./keys/server.public.pem');
    include_once './Crypt/RSA.php';
    $rsa = new Crypt_RSA();
    $rsa->loadKey($publickey); // public key
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
    $ciphertext = $rsa->encrypt($string);
    return base64_encode($ciphertext);
}

function rsaDecrypt($ciphertext){
    include_once './Crypt/RSA.php';
    $privateKey = @file_get_contents('./keys/client.private.pem');
    $ciphertext = base64_decode(str_replace(' ', '+', $ciphertext));
    $rsa = new Crypt_RSA();
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
    $rsa->loadKey($privateKey);
    $plaintext = $rsa->decrypt($ciphertext);
    return $plaintext;
}

?>