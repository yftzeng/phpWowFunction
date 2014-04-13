<?php

include __DIR__.'/bootstrap.php';

use Wow\Util\WowFunction as F;

$encode = F::encode('data');
$decode = F::decode($encode);
echo "encode        => $encode\n";
echo "decode        => $decode\n";

$key = '1234567812345678';
$iv  = '1234567812345678';

$aes_encode = F::aesCtrEncode('data', $key, $iv);
$aes_decode = F::aesCtrDecode($aes_encode, $key, $iv);
echo "aes_encode        => $aes_encode\n";
echo "aes_decode        => $aes_decode\n";

F::setEncryptKey($key);
F::setEncryptIv($iv);

$aes_encode = F::aesCtrEncode('data', $key, $iv);
$aes_decode = F::aesCtrDecode($aes_encode, $key, $iv);
echo "aes_encode        => $aes_encode\n";
echo "aes_decode        => $aes_decode\n";

echo "currenttime       => " . F::currentTime() . "\n";
echo "currenttime (UTC) => " . F::currentUtcTime() . "\n";

echo "randomString      => " . F::randomString(6) . "\n";

$base64url_encode = F::base64UrlEncode('url');
$base64url_decode = F::base64UrlDecode($base64url_encode);
echo "base64UrlEncode   => $base64url_encode\n";
echo "base64UrlDecode   => $base64url_decode\n";

