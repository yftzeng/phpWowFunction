<?php

include __DIR__.'/bootstrap.php';

use Wow\Util\WowFunction as F;

$key = '1234567812345678';
$iv  = '1234567812345678';

$aes_encode = F::aesEncode('data', $key, $iv);
$aes_decode = F::aesDecode($aes_encode, $key, $iv);
echo "aes_encode        => $aes_encode\n";
echo "aes_decode        => $aes_decode\n";

echo "currenttime       => " . F::currentTime() . "\n";
echo "currenttime (UTC) => " . F::currentUtcTime() . "\n";

echo "randomString      => " . F::randomString(6) . "\n";

$base64url_encode = F::base64UrlEncode('url');
$base64url_decode = F::base64UrlDecode($base64url_encode);
echo "base64UrlEncode   => $base64url_encode\n";
echo "base64UrlDecode   => $base64url_decode\n";

