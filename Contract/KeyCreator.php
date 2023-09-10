<?php
declare(strict_types=1);

namespace WebPush\Contract;

use WebPush\Exception\KeyCreateFailure;

interface KeyCreator
{
    /**
     * Get the private key for the newly created key.
     *
     * @return string Private key in PEM format
     * @throws KeyCreateFailure if the key creation fails
     */
    public function privateKey(): string;

    /**
     * Get the public key for the newly created key.
     *
     * @return string Public key in PEM format
     * @throws KeyCreateFailure if the key creation fails
     */
    public function publicKey(): string;
}