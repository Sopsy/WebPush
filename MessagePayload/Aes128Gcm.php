<?php
declare(strict_types=1);

namespace WebPush\MessagePayload;

use Exception;
use WebPush\Contract\KeyCreator;
use WebPush\Contract\MessagePayload;
use WebPush\Exception\KeyCreateFailure;
use WebPush\Exception\KeyFileConversionFailure;
use WebPush\Exception\PayloadTooLarge;
use WebPush\KeyConverter;
use RuntimeException;

use function chr;
use function hash_hkdf;
use function in_array;
use function mb_strlen;
use function openssl_encrypt;
use function openssl_get_cipher_methods;
use function openssl_pkey_derive;
use function pack;
use function random_bytes;
use function sprintf;
use function str_repeat;
use function strlen;

use const OPENSSL_RAW_DATA;

final class Aes128Gcm implements MessagePayload
{
    private const PAYLOAD_MAX_LENGTH = 3993;
    private readonly string $privateKey;
    private readonly string $publicKey;
    private string $encryptedPayload = '';
    // 4096 bytes - content header (86 bytes) - AEAD authentication tag (16 bytes) - padding delimiter (1 byte)
    private string $encryptionSalt = '';

    /**
     * Aes128Gcm constructor.
     *
     * @param KeyCreator $keyFactory
     * @param string $authKey Auth key from the push subscription, Base64Url decoded
     * @param string $receiverPublicKey Public key from the push subscription in PEM format
     * @param string $payload Payload to be encrypted
     * @throws KeyCreateFailure
     * @throws PayloadTooLarge
     */
    public function __construct(
        KeyCreator $keyFactory,
        private readonly string $authKey,
        private readonly string $receiverPublicKey,
        private string $payload
    ) {
        if (strlen($payload) > self::PAYLOAD_MAX_LENGTH) {
            throw new PayloadTooLarge(
                sprintf('Payload too large for Web Push, max size is %d bytes', self::PAYLOAD_MAX_LENGTH)
            );
        }

        // Create a new ECDH key pair
        $this->privateKey = $keyFactory->privateKey();
        $this->publicKey = $keyFactory->publicKey();
    }

    public function contentType(): string
    {
        return 'application/octet-stream';
    }

    public function contentEncoding(): string
    {
        return 'aes128gcm';
    }

    /**
     * Get the Content-Length for data returned with get(), used as a POST header.
     *
     * @return int unsigned
     * @throws RuntimeException in case aes-128-gcm is not supported on this install
     * @throws KeyFileConversionFailure
     */
    public function contentLength(): int
    {
        if ($this->encryptedPayload === '') {
            $this->encrypt();
        }

        return mb_strlen($this->encryptedPayload, '8bit');
    }

    /**
     * Get the encrypted payload, returns the encrypted payload
     *
     * @return string aes-128-gcm encrypted payload with padding
     * @throws RuntimeException in case aes-128-gcm is not supported on this install
     * @throws KeyFileConversionFailure
     */
    public function payload(): string
    {
        if ($this->encryptedPayload === '') {
            $this->encrypt();
        }

        return $this->encryptedPayload;
    }

    /**
     * Encrypt the payload with AES-128-GCM
     *
     * @throws RuntimeException in case aes-128-gcm is not supported on this install
     * @throws KeyFileConversionFailure
     */
    private function encrypt(): void
    {
        $cipher = 'aes-128-gcm';

        if (!in_array($cipher, openssl_get_cipher_methods(), true)) {
            throw new RuntimeException($cipher . ' is not supported by this OpenSSL install.');
        }

        // Derive all needed parameters for AES-128-GCM encryption
        try {
            $this->encryptionSalt = random_bytes(16);
        } catch (Exception $e) {
            throw new RuntimeException('Could not generate a cryptographically secure salt.', 1, $e);
        }
        $ikm = $this->ikm();
        $nonce = hash_hkdf('sha256', $ikm, 12, 'Content-Encoding: nonce' . "\x00", $this->encryptionSalt);
        $contentEncryptionKey = hash_hkdf(
            'sha256',
            $ikm,
            16,
            'Content-Encoding: aes128gcm' . "\x00",
            $this->encryptionSalt
        );

        // Add padding to prevent figuring out the content by its size
        $this->payload .= $this->padding(self::PAYLOAD_MAX_LENGTH - mb_strlen($this->payload, '8bit'));

        // Encrypt
        $encrypted = openssl_encrypt($this->payload, $cipher, $contentEncryptionKey, OPENSSL_RAW_DATA, $nonce, $tag);

        // Payload = Header + encrypted content + AEAD authentication tag
        $this->encryptedPayload = $this->contentHeader() . $encrypted . $tag;
    }

    /**
     * Get the Input Keying Material (IKM) used when deriving the content encryption key.
     * See RFC 8291, section 3.3 for details
     *
     * @return string HKDF derived key
     * @throws KeyFileConversionFailure if the conversion of a PEM key to DER fails - should never happen
     */
    private function ikm(): string
    {
        $keyLen = strlen($this->privateKey);
        $sharedSecret = openssl_pkey_derive($this->receiverPublicKey, $this->privateKey, $keyLen);
        $publicKey = KeyConverter::unserializePublicPem($this->publicKey);
        $receiverPublicKey = KeyConverter::unserializePublicPem($this->receiverPublicKey);
        $info = 'WebPush: info' . "\x00" . $receiverPublicKey . $publicKey;

        return hash_hkdf('sha256', (string)$sharedSecret, 32, $info, $this->authKey);
    }

    /**
     * Get padding for plaintext payload.
     * The separator (0x02) is always needed in the payload. The number of NULL bytes can vary.
     *
     * @param int $length Padding length, payload usually padded to max size for security
     * @return string Padding string which should be concatenated to the plaintext payload
     */
    private function padding(int $length): string
    {
        return "\x02" . str_repeat("\x00", $length);
    }

    /**
     * Get the AES-128-GCM header, which includes necessary data for the receiver to decrypt the payload.
     * See RFC 8188, section 2.1 for details
     *
     * @return string Content header string in binary format, prepended to the encrypted payload
     * @throws KeyFileConversionFailure if the conversion of a PEM key to DER fails - should never happen
     */
    private function contentHeader(): string
    {
        $publicKey = KeyConverter::unserializePublicPem($this->publicKey);

        return $this->encryptionSalt . pack('N', 4096) . chr(mb_strlen($publicKey, '8bit')) . $publicKey;
    }
}