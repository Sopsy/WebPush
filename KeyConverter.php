<?php
declare(strict_types=1);

namespace WebPush;

use InvalidArgumentException;
use WebPush\Exception\KeyFileConversionFailure;

use function base64_decode;
use function base64_encode;
use function chunk_split;
use function mb_strlen;
use function mb_strpos;
use function mb_substr;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;

final class KeyConverter
{
    // DER header - for secp256r1 it's always this and we don't need anything else for Web Push
    private static string $derHeader = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

    /**
     * OpenSSL requires a header for the key to be usable, the header contains e.g. the curve used.
     * Note: NIST P-256, secp256r1 and prime256v1 are all the same curve.
     * secp256k1 on the other hand is a different beast. Do not confuse.
     *
     * @param string $key 65 byte long public key
     * @return string PEM formatted secp256r1 public key for OpenSSL
     */
    public static function p256PublicKeyToPem(string $key): string
    {
        if (mb_strpos($key, "\x04", 0, '8bit') !== 0) {
            throw new InvalidArgumentException('Only uncompressed keys are supported (starting with 0x04)');
        }

        $dataLength = mb_strlen($key, '8bit');

        // secp256r1 should always be 64 bytes of data + 1 byte of header
        if ($dataLength !== 65) {
            throw new InvalidArgumentException('Invalid key, wrong length');
        }

        $key = self::$derHeader . $key;

        $key = chunk_split(base64_encode($key), 64, "\n");

        return "-----BEGIN PUBLIC KEY-----\n" . $key . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Gets the public key from a private key in PEM format and returns it serialized to bytes
     *
     * @param string $privateKey PEM private key
     * @return string PEM public key
     * @throws KeyFileConversionFailure if the conversion of PEM to DER fails
     */
    public static function unserializePublicFromPrivate(string $privateKey): string
    {
        $publicKey = self::getPublicFromPrivate($privateKey);

        return self::unserializePublicPem($publicKey);
    }

    /**
     * Gets the public key from a private key in PEM format
     *
     * @param string $privateKey PEM private key
     * @return string PEM public key
     */
    public static function getPublicFromPrivate(string $privateKey): string
    {
        $key = openssl_pkey_get_private($privateKey);
        $publicKey = false;
        if ($key) {
            $publicKey = openssl_pkey_get_details($key);
        }

        if ($publicKey === false || !isset($publicKey['key'])) {
            throw new InvalidArgumentException('Invalid private key, maybe not in PEM format (' . openssl_error_string() . ')');
        }

        return (string)$publicKey['key'];
    }

    /**
     * Returns the public key serialized to bytes from a PEM key
     *
     * @param string $publicKey PEM public key
     * @return string raw public key in binary format
     * @throws KeyFileConversionFailure if the conversion of PEM to DER fails
     * @throws InvalidArgumentException if the string does not contain a valid secp256r1 key
     */
    public static function unserializePublicPem(string $publicKey): string
    {
        $publicKey = self::pem2der($publicKey);

        return self::unserializePublicDer($publicKey);
    }

    /**
     * Converts a PEM key to a DER key.
     *
     * @param string $pem key in PEM format
     * @return string key in DER format
     * @throws KeyFileConversionFailure if the conversion fails
     */
    public static function pem2der(string $pem): string
    {
        $begin = 'KEY-----';
        $end = '-----END';

        $pem = mb_substr($pem, mb_strpos($pem, $begin, 0, '8bit') ?: mb_strlen($begin, '8bit'), null, '8bit');
        $pem = mb_substr($pem, 0, mb_strpos($pem, $end, 0, '8bit') ?: 0, '8bit');
        $der = base64_decode($pem);

        if (!$der) {
            throw new KeyFileConversionFailure('Could not convert PEM to DER. Possibly invalid key.');
        }

        return $der;
    }

    /**
     * Returns the public key serialized to bytes from a DER key
     *
     * @param string $publicKey DER public key
     * @return string raw public key in binary format
     * @throws InvalidArgumentException if the string is not a valid DER secp256r1 key
     */
    public static function unserializePublicDer(string $publicKey): string
    {
        return self::stripDerHeader($publicKey);
    }

    /**
     * Strips the DER header from a key string
     *
     * @param string $key DER formatted secp256r1 key
     * @return string Key without the DER header
     * @throws InvalidArgumentException if the string is not a valid DER secp256r1 key
     */
    public static function stripDerHeader(string $key): string
    {
        $headerLength = mb_strlen(self::$derHeader, '8bit');

        if (mb_strpos($key, self::$derHeader, 0, '8bit') !== 0) {
            throw new InvalidArgumentException('Invalid DER file, not secp256r1 header.');
        }

        return mb_substr($key, $headerLength, null, '8bit');
    }

    /**
     * Returns the public key serialized to bytes from a base64 encoded DER key
     *
     * @param string $publicKey base64 encoded DER public key
     * @return string raw public key in binary format
     * @throws InvalidArgumentException if the string is not a valid DER secp256r1 key
     */
    public static function unserializePublicBase64(string $publicKey): string
    {
        $publicKey = base64_decode($publicKey);

        return self::unserializePublicDer($publicKey);
    }
}