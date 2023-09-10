<?php
declare(strict_types=1);

namespace WebPush;

use InvalidArgumentException;
use BaseNEncoder\Encoder;
use BaseNEncoder\Scheme\Base64Url;
use Jwt\Contract\Jwt;
use Jwt\Exception\SignerFailure;
use WebPush\Contract\MessagePayload;
use WebPush\Contract\MessageUrgency;
use WebPush\Contract\Response;
use WebPush\Exception\KeyFileConversionFailure;
use WebPush\MessageUrgency\Normal;

use function curl_close;
use function curl_error;
use function curl_exec;
use function curl_getinfo;
use function curl_init;
use function curl_setopt;
use function filter_var;
use function mb_strlen;
use function preg_match;
use function str_starts_with;
use function trim;

use const CURL_IPRESOLVE_V4;
use const CURLINFO_RESPONSE_CODE;
use const CURLOPT_CONNECTTIMEOUT;
use const CURLOPT_HTTPHEADER;
use const CURLOPT_IPRESOLVE;
use const CURLOPT_POST;
use const CURLOPT_POSTFIELDS;
use const CURLOPT_RETURNTRANSFER;
use const CURLOPT_SSL_VERIFYPEER;
use const CURLOPT_TIMEOUT;
use const CURLOPT_URL;
use const FILTER_VALIDATE_URL;

final class PushMessage
{
    private readonly string $serverPublicKey;
    private MessageUrgency $urgency;

    /**
     * @param Jwt $jwt
     * @param string $endpoint Full endpoint URL from the browser
     * @param string $serverKey The server private key in PEM format
     * @param int $ttl TTL value in seconds - How long should the push service try to deliver the message. A value of 0
     *     will try to deliver it once immediately and gives up if it fails.
     * @param string $topic
     * @param MessageUrgency|null $urgency
     * @throws KeyFileConversionFailure if the conversion of a PEM key to DER fails, maybe due to an invalid key
     *     supplied
     */
    public function __construct(
        private readonly Jwt $jwt,
        private readonly string $endpoint,
        string $serverKey,
        private readonly int $ttl = 2419200,
        private string $topic = '',
        ?MessageUrgency $urgency = null
    ) {
        if (!str_starts_with($endpoint, 'https://')) {
            throw new InvalidArgumentException('Invalid endpoint URL');
        }

        if (!$this->validateEndpointUrl($endpoint)) {
            throw new InvalidArgumentException('Invalid endpoint URL');
        }

        if ($ttl < 0) {
            throw new InvalidArgumentException('TTL cannot be negative');
        }

        if ($ttl > 2419200) {
            throw new InvalidArgumentException('Max TTL is 2419200 seconds');
        }

        $this->urgency = $urgency ?? new Normal();

        $this->serverPublicKey = KeyConverter::unserializePublicFromPrivate($serverKey);
    }

    /**
     * Set the message urgency, use reasonable values to save users' battery.
     *
     * @param MessageUrgency $urgency very-low, low, normal or high
     * @return PushMessage
     */
    public function withUrgency(MessageUrgency $urgency): self
    {
        $clone = clone $this;
        $clone->urgency = $urgency;

        return $clone;
    }

    /**
     * Set the topic of the push message. If the push service supports it, only the last message
     * with the same topic is shown to the user if there is multiple undelivered messages in queue
     * e.g. due to user being offline.
     *
     * @param string $topic
     * @return PushMessage
     * @throws InvalidArgumentException if the topic length exceeds 32 bytes or contains invalid characters
     */
    public function withTopic(string $topic): self
    {
        if (mb_strlen($topic, '8bit') > 32) {
            throw new InvalidArgumentException('Topic too long');
        }

        if (!preg_match('/^[A-Za-z\d\-_]$/', $topic)) {
            throw new InvalidArgumentException('Topic contains characters that are not URL-safe');
        }

        $clone = clone $this;
        $clone->topic = $topic;

        return $clone;
    }

    /**
     * Send the Push Message to the specified endpoint
     *
     * @param MessagePayload $payload
     * @return Response
     * @throws SignerFailure if signing the JWT fails
     */
    public function send(MessagePayload $payload): Response
    {
        $ch = curl_init();

        $headers = [
            'Authorization: vapid t=' . $this->jwt->signedJwt() . ', k=' . (new Encoder(new Base64Url()))->encode($this->serverPublicKey, false),
            'TTL: ' . $this->ttl,
        ];

        if ($this->topic !== '') {
            $headers[] = 'Topic: ' . $this->topic;
        }

        $headers[] = 'Urgency: ' . $this->urgency->name();
        $headers[] = 'Content-Type: ' . $payload->contentType();
        $headers[] = 'Content-Encoding: ' . $payload->contentEncoding();
        $headers[] = 'Content-Length: ' . $payload->contentLength();
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload->payload());
        curl_setopt($ch, CURLOPT_URL, $this->endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $responseCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

        if ($response === false) {
            $response = 'CURL error: ' . curl_error($ch);
        }

        $response = new PushServiceResponse($responseCode, (string)$response);

        curl_close($ch);

        return $response;
    }

    private function validateEndpointUrl(string $url): bool
    {
        $url = trim($url);

        // All endpoints should always use HTTPS
        if (!str_starts_with($url, 'https://')) {
            return false;
        }

        /**
         * @noinspection BypassedUrlValidationInspection
         * Prior strpos validation of protocol should make us safe already
         */
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
}