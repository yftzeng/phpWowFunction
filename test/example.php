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

echo "####################\n";
echo "### Date\n";
echo "####################\n";

$current_time1 = date('Y-m-d', strtotime("2014-05-31"));
$current_time2 = date('Y-m-d', strtotime("2014-05-15"));
$current_time3 = date('Y-m-d', strtotime("2014-12-31"));
$current_time4 = date('Y-m-d', strtotime("2014-12-01"));
$current_time5 = date('Y-m-d', strtotime("2014-02-28"));

$test1 = date('Y-m-d', F::getPreciseNextMonth($current_time1));
if ($test1 !== '2014-06-30') {
    echo "Error 1\n";
    exit;
}

$test2 = date('Y-m-d', F::getPreciseNextMonth($current_time2));
if ($test2 !== '2014-06-15') {
    echo "Error 2\n";
    exit;
}

$test3 = date('Y-m-d', F::getPreciseNextMonth($current_time3));
if ($test3 !== '2015-01-31') {
    echo "Error 3\n";
    exit;
}

$test4 = date('Y-m-d', F::getPreciseNextMonth($current_time4));
if ($test4 !== '2015-01-01') {
    echo "Error 4\n";
    exit;
}

$test5 = date('Y-m-d', F::getPreciseNextMonth($current_time5));
if ($test5 !== '2014-03-28') {
    echo "Error 5\n";
    exit;
}

echo "...pass\n";
