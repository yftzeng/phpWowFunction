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
    function randomString($len, $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    {
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
     * @comment async http get by curl
     *
     * @return string|boolean
     */
    public static function curlGetAsync($url, $timeout = null)
    {
        if (null === $timeout) {
            $timeout = self::$_default_conn_timeout;
        }

        $parts = parse_url($url);

        $fp = fsockopen(
            $parts['host'],
            isset($parts['port'])?$parts['port']:80,
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
            $query .= '?' . $parts['query'];
        }

        $out = "GET ".$query." HTTP/1.1\r\n";
        $out.= "Host: ".$parts['host']."\r\n";
        $out.= "Connection: Close\r\n\r\n";
        if (isset($params)) {
            $out.= $params;
        }

        fwrite($fp, $out);
        fclose($fp);
    }

    /**
     * @param string $url     url
     * @param string $params  url parameters
     * @param string $timeout sencods for connection timeout
     *
     * @comment async http post by curl
     * http://petewarden.typepad.com/searchbrowser/2008/06/how-to-post-an.html
     * http://w-shadow.com/blog/2007/10/16/how-to-run-a-php-script-in-the-background/
     * Modified by: yftzeng (yftzeng@gmail.com)
     *
     * @return string|boolean
     */
    public static function curlPostAsync($url, $params = null, $timeout = null)
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

        $fp = fsockopen(
            $parts['host'],
            isset($parts['port'])?$parts['port']:80,
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
        $out.= "Connection: Close\r\n\r\n";
        if (isset($params)) {
            $out.= $params;
        }

        fwrite($fp, $out);
        fclose($fp);
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
     * @param string $key  encryption key
     * @param string $iv   initialization vector
     *
     * @comment aes 256 ctr encryption encode
     *
     * @return string
     */
    public static function aesEncode($data, $key, $iv)
    {
        return openssl_encrypt($data, 'AES-256-CTR', $key, false, $iv);
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
    public static function aesDecode($data, $key, $iv)
    {
        return openssl_decrypt($data, 'AES-256-CTR', $key, false, $iv);
    }
}