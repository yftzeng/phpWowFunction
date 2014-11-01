<?php
/**
 * PHP Wow Function
 *
 * PHP version 5
 *
 * @category Wow
 * @package  Util
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT
 * @link     https://github.com/yftzeng/phpWowFunction
 */

namespace Wow\Util;

/**
 * PHP Wow Function
 *
 * @category Wow
 * @package  Util
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT
 * @link     https://github.com/yftzeng/phpWowFunction
 */
class WowFunction
{

    private static $_default_conn_timeout = 5;
    private static $_encrypt_alg = 'AES-256-CTR';
    private static $_encrypt_key = '1234567812345678';
    private static $_encrypt_iv = '1234567812345678';

    private static $_STRING_EXCL = true;
    private static $_STRING_INCL = false;
    private static $_STRING_BEFORE = true;
    private static $_STRING_AFTER = false;

    /**
     * @param string $alg encryption algorithm
     *
     * @comment set encryption algorithm
     *
     * @return void
     */
    public static function setEncryptAlg($alg)
    {
        self::$_encrypt_alg = $alg;
    }

    /**
     * @param string $key encryption key
     *
     * @comment set encryption key
     *
     * @return void
     */
    public static function setEncryptKey($key)
    {
        self::$_encrypt_key = $key;
    }

    /**
     * @param string $iv encryption iv
     *
     * @comment set encryption iv
     *
     * @return void
     */
    public static function setEncryptIv($iv)
    {
        self::$_encrypt_iv = $iv;
    }

    /**
     * @comment return current time
     *
     * @return string
     */
    public static function currentTime()
    {
        return date('Y-m-d H:i:s');
    }

    /**
     * @comment return current date
     *
     * @return string
     */
    public static function currentDate()
    {
        return date('Y-m-d');
    }

    /**
     * @comment return current time of GMT/UTC
     *
     * @return string
     */
    public static function currentUtcTime()
    {
        return gmdate('Y-m-d H:i:s');
    }

    /**
     * @comment return current date of GMT/UTC
     *
     * @return string
     */
    public static function currentUtcDate()
    {
        return gmdate('Y-m-d');
    }

    /**
     * @param string $data data
     *
     * @comment hex to binary
     *
     * @return mixed
     */
    public static function hex2bin($data)
    {
        return pack('H*', bin2hex($data));
    }

    /**
     * @param string $data data
     *
     * @comment xml to array
     *
     * @return array
     */
    public static function xml2array($data)
    {
        return json_decode(
            json_encode(
                simplexml_load_string(
                    $data, 'SimpleXMLElement', LIBXML_NOCDATA
                )
            ), true
        );
    }

    /**
     * @param string $root   xml root
     * @param string $return operation string
     *
     * @comment assocArrayToXML
     *
     * @return string
     */
    public static function assocArrayToXML($root, $return)
    {
        $xml = new SimpleXMLElement("<?xml version=\"1.0\" encoding=\"utf-8\" ?"."><{$root}></{$root}>");
        $f = create_function(
            '$f,$c,$a', '
            foreach($a as $k=>$v) {
                if(is_array($v)) {
                    $ch=$c->addChild($k);
                    $f($f,$ch,$v);
            } else {
                $c->addChild($k,$v);
            }
            }'
        );
        $f($f,$xml,$ar);
        return $xml->asXML();
    }

    /**
     * @param bool $dashes with dashes or not
     *
     * @comment UUIDv4 generater by OpenSSL
     *
     * @return string
     */
    public static function uuidv4ByOpenssl($dashes = true)
    {
        $data = openssl_random_pseudo_bytes(16);

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0010
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        if ($dashes === true) {
            return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
        }
        return vsprintf('%s%s%s%s%s%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * @param bool $dashes with dashes or not
     *
     * @comment UUIDv4 generater by Uniqid with SERVER_ADDR
     *
     * @return string
     */
    public static function uuidv4Ex($dashes = true)
    {
        $data = substr(
            str_replace('.', '', uniqid('', true))
            . str_pad(crc32($_SERVER['SERVER_ADDR']), 10, '0', STR_PAD_LEFT), 0, 32
        );

        if ($dashes === true) {
            return substr($data, 0, 8) . '-'
                . substr($data, 8, 4) . '-'
                . substr($data, 12, 4) . '-'
                . substr($data, 16, 4) . '-'
                . substr($data, 20, 12);
        } else {
            return $data;
        }
    }

    /**
     * @param bool $dashes with dashes or not
     *
     * @comment IPv6, for example: 2001:0db8:85a3:08d3:1319:8a2e:0370:7344
     * @comment maxlength of IPv6 in crc32 is 10.
     * @comment result length will fix in 32(without dashes)+10 = 42,
     * @comment or 36(with dashes)+10 = 46
     *
     * @return string
     */
    public static function uuidv4ByOpensslEx($dashes = true)
    {

        $data = openssl_random_pseudo_bytes(16);

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0010
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        if ($dashes === true) {
            return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4))
                . str_pad(crc32($_SERVER['SERVER_ADDR']), 10, '0', STR_PAD_LEFT);
        }
        return vsprintf('%s%s%s%s%s%s%s%s', str_split(bin2hex($data), 4))
            . str_pad(crc32($_SERVER['SERVER_ADDR']), 10, '0', STR_PAD_LEFT);
    }

    /**
     * @param string $len        length of random_string
     * @param string $characters characters string for random selection
     *
     * @comment generate random string
     *
     * @return string
     */
    function randomString(
        $len,
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    ) {
        $len = (int)$len;
        $char_len = strlen($characters) - 1;
        $string = '';
        while ($len--) {
            $string .= $characters[mt_rand(0, $char_len)];
        }
        return $string;
    }

    /**
     * @param string $url     url
     * @param string $timeout sencods for connection timeout
     *
     * @comment http get by curl
     *
     * @return string|boolean
     */
    public static function curlGet($url, $timeout = null)
    {
        if (null === $timeout) {
            $timeout = self::$_default_conn_timeout;
        }

        $ch = curl_init();
        $options = array(CURLOPT_URL => $url,
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout
        );
        curl_setopt_array($ch, $options);
        $output = curl_exec($ch);
        if ($output === false || curl_getinfo($ch, CURLINFO_HTTP_CODE) !== 200) {
            curl_close($ch);
            return false;
        }
        curl_close($ch);
        return $output;
    }

    /**
     * @param string $url     url
     * @param string $params  url parameters
     * @param string $timeout sencods for connection timeout
     *
     * @comment http post by curl
     *
     * @return string|boolean
     */
    public static function curlPost($url, $params = null, $timeout = null)
    {
        if (null === $timeout) {
            $timeout = self::$_default_conn_timeout;
        }

        if (null !== $params && is_array($params)) {
            foreach ($params as $key => &$val) {
                if (is_array($val)) {
                    $val = implode(',', $val);
                }
                $post_params[] = $key.'='.urlencode($val);
            }
            $params = implode('&', $post_params);
        }

        $ch = curl_init();
        $options = array(CURLOPT_URL => $url,
            CURLOPT_HEADER => false,
            CURLOPT_POST => 1,
            CURLOPT_POSTFIELDS => "$params",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout
        );
        curl_setopt_array($ch, $options);
        $output = curl_exec($ch);
        if ($output === false || curl_getinfo($ch, CURLINFO_HTTP_CODE) !== 200) {
            curl_close($ch);
            return false;
        }
        curl_close($ch);
        return $output;
    }

    /**
     * @param string $url     url
     * @param string $timeout sencods for connection timeout
     *
     * @comment async http get by fsockopen
     *
     * @return boolean
     */
    public static function httpGet($url, $timeout = null)
    {
        if (null === $timeout) {
            $timeout = self::$_default_conn_timeout;
        }

        $parts = parse_url($url);

        $scheme = '';
        $port = 80;
        if ($parts['scheme'] === 'https') {
            $scheme = 'ssl://';
            $port = 443;
        }

        $fp = fsockopen(
            $scheme . $parts['host'],
            isset($parts['port'])?$parts['port']:$port,
            $errno, $errstr, $timeout
        );

        if (!$fp) {
            return false;
        }

        $query = '/';
        if (isset($parts['path'])) {
            $query = $parts['path'];
        }
        if (isset($parts['query'])) {
            if (is_array($parts['query'])) {
                $query .= '?' . http_build_query($parts['query']);
            } else {
                $query .= '?' . $parts['query'];
            }
        }

        $out = "GET ".$query." HTTP/1.1\r\n";
        $out.= "Host: ".$parts['host']."\r\n";
        //$out.= "Accept-Encoding: gzip, deflate, compress;q=0.9\r\n";
        $out.= "Connection: Close\r\n\r\n";
        if (isset($params)) {
            $out.= $params;
        }

        fwrite($fp, $out);
        fclose($fp);
        return true;
    }

    /**
     * @param string $url     url
     * @param string $params  url parameters
     * @param string $timeout sencods for connection timeout
     *
     * @comment async http post by fsockopen
     * http://petewarden.typepad.com/searchbrowser/2008/06/how-to-post-an.html
     * http://w-shadow.com/blog/2007/10/16/how-to-run-a-php-script-in-the-background/
     * Modified by: yftzeng (yftzeng@gmail.com)
     *
     * @return boolean
     */
    public static function httpPost($url, $params = null, $timeout = null)
    {
        if (null === $timeout) {
            $timeout = self::$default_conn_timeout;
        }

        if (null !== $params && is_array($params)) {
            foreach ($params as $key => &$val) {
                if (is_array($val)) {
                    $val = implode(',', $val);
                }
                $post_params[] = $key.'='.urlencode($val);
            }
            $params = implode('&', $post_params);
        }

        $parts = parse_url($url);

        $scheme = '';
        $port = 80;
        if ($parts['scheme'] === 'https') {
            $scheme = 'ssl://';
            $port = 443;
        }

        $fp = fsockopen(
            $scheme . $parts['host'],
            isset($parts['port'])?$parts['port']:$port,
            $errno, $errstr, $timeout
        );

        if (!$fp) {
            return false;
        }

        $parts['path'] = isset($parts['path']) ? $parts['path'] : '/';

        $out = "POST ".$parts['path']." HTTP/1.1\r\n";
        $out.= "Host: ".$parts['host']."\r\n";
        $out.= "Content-Type: application/x-www-form-urlencoded\r\n";
        $out.= "Content-Length: ".strlen($params)."\r\n";
        //$out.= "Accept-Encoding: gzip, deflate, compress;q=0.9\r\n";
        $out.= "Connection: Close\r\n\r\n";
        if (isset($params)) {
            $out.= $params;
        }

        fwrite($fp, $out);
        fclose($fp);
        return true;
    }

    /**
     * @param string $data data
     *
     * @comment return safe base64 url encode
     *
     * @return string
     */
    public static function base64UrlEncode($data)
    {
        return strtr(base64_encode($data), '+/', '-_');
        // Reduce string size
        //return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $data data
     *
     * @comment return safe base64 url decode
     *
     * @return string
     */
    public static function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
        // Compatible with RFC 4648 (http://tools.ietf.org/html/rfc4648)
        /* *
        return base64_decode(
            str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT)
        );
         */
    }

    /**
     * @param string $data data
     * @param string $alg  encryption algorithm
     * @param string $key  encryption key
     * @param string $iv   initialization vector
     *
     * @comment encryption
     *
     * @return string
     */
    public static function encode($data, $alg = null, $key = null, $iv = null)
    {
        if ($alg !== null) {
            self::$_encrypt_alg = $alg;
        }
        if ($key !== null) {
            self::$_encrypt_key = $key;
        }
        if ($iv !== null) {
            self::$_encrypt_iv = $iv;
        }
        return openssl_encrypt(
            $data, self::$_encrypt_alg,
            self::$_encrypt_key,
            false,
            self::$_encrypt_iv
        );
    }

    /**
     * @param string $data data
     * @param string $alg  encryption algorithm
     * @param string $key  encryption key
     * @param string $iv   initialization vector
     *
     * @comment decryption
     *
     * @return string
     */
    public static function decode($data, $alg = null, $key = null, $iv = null)
    {
        if ($alg !== null) {
            self::$_encrypt_alg = $alg;
        }
        if ($key !== null) {
            self::$_encrypt_key = $key;
        }
        if ($iv !== null) {
            self::$_encrypt_iv = $iv;
        }
        return openssl_decrypt(
            $data, self::$_encrypt_alg,
            self::$_encrypt_key,
            false,
            self::$_encrypt_iv
        );
    }

    /**
     * @param string $data data
     * @param string $key  encryption key
     * @param string $iv   initialization vector
     *
     * @comment aes 256 ctr encryption encode
     *
     * @return string
     */
    public static function aesCtrEncode($data, $key = null, $iv = null)
    {
        if ($key !== null) {
            self::$_encrypt_key = $key;
        }
        if ($iv !== null) {
            self::$_encrypt_iv = $iv;
        }
        return openssl_encrypt(
            $data, 'AES-256-CTR', self::$_encrypt_key, false, self::$_encrypt_iv
        );
    }

    /**
     * @param string $data data
     * @param string $key  encryption key
     * @param string $iv   initialization vector
     *
     * @comment aes 256 ctr encryption decode
     *
     * @return string
     */
    public static function aesCtrDecode($data, $key = null, $iv = null)
    {
        if ($key !== null) {
            self::$_encrypt_key = $key;
        }
        if ($iv !== null) {
            self::$_encrypt_iv = $iv;
        }
        return openssl_decrypt(
            $data, 'AES-256-CTR', self::$_encrypt_key, false, self::$_encrypt_iv
        );
    }

    /**
     * @param string  $string     string
     * @param string  $delineator string delineator
     * @param string  $desired    desired string
     * @param boolean $type       boolean type
     *
     * @comment string split function
     *
     * @return string
     */
    public static function stringSplit($string, $delineator, $desired, $type)
    {
        // Case insensitive parse, convert string and delineator to lower case
        $lc_str = strtolower($string);
        $marker = strtolower($delineator);

        // Return text BEFORE the delineator
        if ($desired === self::$_STRING_BEFORE) {
            if ($type === self::$_STRING_EXCL) {
                // Return text ESCL of the delineator
                $split_here = strpos($lc_str, $marker);
            } else {
                // Return text INCL of the delineator
                $split_here = strpos($lc_str, $marker) + strlen($marker);
            }

            $parsed_string = substr($string, 0, $split_here);
        } else {
            // Return text AFTER the delineator
            if ($type === self::_STRING_EXCL) {
                // Return text ESCL of the delineator
                $split_here = strpos($lc_str, $marker) + strlen($marker);
            } else {
                // Return text INCL of the delineator
                $split_here = strpos($lc_str, $marker);
            }

            $parsed_string =  substr($string, $split_here, strlen($string));
        }
        return $parsed_string;
    }

    /**
     * @param string  $string string
     * @param string  $start  string start
     * @param string  $stop   string stop
     * @param boolean $type   boolean type
     *
     * @comment string between function
     *
     * @return string
     */
    public static function stringReturnBetween($string, $start, $stop, $type)
    {
        return stringSplit(
            stringSplit(
                $string, $start, self::$_STRING_AFTER, $type
            ), $stop, self::$_STRING_BEFORE, $type
        );
        //$temp = stringSplit($string, $start, self::$_STRING_AFTER,, $type);
        //return stringSplit($temp, $stop, self::$_STRING_BEFORE,, $type);
    }

    /**
     * @param string $timestamp time string
     *
     * @comment get precise next month
     *
     * @return int
     */
    public static function getPreciseNextMonth($timestamp)
    {
        $int_month_of_time    = (int) date('m', strtotime($timestamp));
        $int_addmonth_of_time = (int) date('m', strtotime($timestamp.'+1 month'));
        if ($int_month_of_time === $int_addmonth_of_time-1
            || $int_month_of_time === 12
        ) {
            return strtotime($timestamp.'+1 month');
        }
        return strtotime($timestamp.'last day of next month');
    }
}
