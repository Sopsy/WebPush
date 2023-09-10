<?php
declare(strict_types=1);

namespace WebPush\KeyCreator;

use WebPush\Contract\KeyCreator;
use WebPush\Exception\KeyCreateFailure;

use function extension_loaded;
use function openssl_pkey_export;
use function openssl_pkey_get_details;

use const OPENSSL_KEYTYPE_EC;

final class OpenSSL implements KeyCreator
{
    // Key types
    public const KEYTYPE_EC = 1;
    // Curve types
    public const CURVE_P256 = 1;
    private readonly int $keyType;
    private readonly string $curve;
    private string $privateKey = '';
    private string $publicKey = '';

    /**
     * Check that the openssl PHP extension is loaded and set parameters for the new key pair, e.g. key type.
     *
     * @param int $keyType Key type, implementation specific
     * @param int $params Implementation specific key parameters, usually bitwise flags
     * @throws KeyCreateFailure For invalid keyType or params
     */
    public function __construct(
        int $keyType,
        int $params = 0
    ) {
        if (!extension_loaded('openssl')) {
            throw new KeyCreateFailure('OpenSSL extension is not loaded');
        }

        if ($keyType === self::KEYTYPE_EC) {
            $this->keyType = OPENSSL_KEYTYPE_EC;
        } else {
            throw new KeyCreateFailure('Unsupported key type: ' . $keyType);
        }

        $defaultCurve = 'prime256v1';
        if ($params & self::CURVE_P256) {
            $this->curve = 'prime256v1';
        } else {
            $this->curve = $defaultCurve;
        }
    }

    public function privateKey(): string
    {
        $this->createKey();

        return $this->privateKey;
    }

    public function publicKey(): string
    {
        $this->createKey();

        return $this->publicKey;
    }

    /**
     * @throws KeyCreateFailure if the key creation fails
     */
    private function createKey(): void
    {
        if ($this->privateKey !== '') {
            return;
        }

        /** @noinspection PhpFullyQualifiedNameUsageInspection - To workaround a bug in PHP Inspections (EA Ultimate) */
        $key = \openssl_pkey_new([
            'curve_name' => $this->curve,
            'private_key_bits' => 4096,
            'private_key_type' => $this->keyType,
        ]);
        if (!$key) {
            throw new KeyCreateFailure('Could not create a key');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['key'])) {
            throw new KeyCreateFailure('Could not get details for the new key');
        }

        if (!openssl_pkey_export($key, $privateKey)) {
            throw new KeyCreateFailure('Could not export the private key');
        }

        $this->privateKey = $privateKey;
        $this->publicKey = (string)$details['key'];
    }
}