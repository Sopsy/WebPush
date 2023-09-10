<?php
declare(strict_types=1);

namespace WebPush;

use WebPush\Contract\Response;

final class PushServiceResponse implements Response
{
    public function __construct(
        private readonly int $responseCode,
        private readonly string $response
    ) {
    }

    public function code(): int
    {
        return $this->responseCode;
    }

    public function message(): string
    {
        return $this->response;
    }

    public function success(): bool
    {
        // If response code is between 200 - 299, sending probably succeeded. Otherwise we assume it failed.
        return $this->responseCode >= 200 && $this->responseCode <= 299;
    }
}