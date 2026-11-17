<?php

declare(strict_types=1);

namespace Hush\Client;

use Hush\Crypto\SealedSecret;
use Hush\Support\Base64Url;
use InvalidArgumentException;

/**
 * PHP client for the Hush API (twin of resources/assets/js/client/api.js).
 * It only ever sends ciphertext and the public header.
 */
final class ApiClient
{
    public function __construct(
        private readonly HttpTransport $transport,
        private readonly string $origin,
    ) {}

    /**
     * Creates, uploads every chunk (one retry on 5xx) and seals.
     *
     * @return array{id: string, deletionToken: string, expiresAt: int}
     */
    public function upload(SealedSecret $sealed, int $expiresIn, int $maxViews): array
    {
        $created = $this->expect(201, $this->transport->send('POST', $this->origin . '/api/secrets', ['Content-Type' => 'application/json'], json_encode([
            'header' => Base64Url::encode($sealed->headerBytes),
            'meta' => Base64Url::encode($sealed->metaRecord),
            'expiresIn' => $expiresIn,
            'maxViews' => $maxViews,
        ], JSON_THROW_ON_ERROR)))->json();
        $id = self::field($created, 'id');
        $token = self::field($created, 'deletionToken');
        $expiresAt = $created['expiresAt'] ?? null;

        foreach ($sealed->chunkRecords() as $index => $record) {
            $send = fn(): HttpResult => $this->transport->send('PUT', "{$this->origin}/api/secrets/{$id}/chunks/{$index}", [
                'Content-Type' => 'application/octet-stream',
                'Authorization' => 'Bearer ' . $token,
            ], $record);
            $result = $send();
            if ($result->status >= 500) {
                $result = $send();
            }
            $this->expect(204, $result);
        }
        $this->expect(200, $this->transport->send('POST', "{$this->origin}/api/secrets/{$id}/seal", ['Authorization' => 'Bearer ' . $token]));

        return ['id' => $id, 'deletionToken' => $token, 'expiresAt' => is_int($expiresAt) ? $expiresAt : 0];
    }

    /**
     * @return array{passwordProtected: bool, viewsLeft: int, expiresAt: int, header: string, meta: string}
     */
    public function status(string $id): array
    {
        $data = $this->expect(200, $this->transport->send('GET', "{$this->origin}/api/secrets/{$id}"))->json();
        try {
            return [
                'passwordProtected' => ($data['passwordProtected'] ?? null) === true,
                'viewsLeft' => is_int($data['viewsLeft'] ?? null) ? $data['viewsLeft'] : 0,
                'expiresAt' => is_int($data['expiresAt'] ?? null) ? $data['expiresAt'] : 0,
                'header' => Base64Url::decode(self::field($data, 'header')),
                'meta' => Base64Url::decode(self::field($data, 'meta')),
            ];
        } catch (InvalidArgumentException) {
            throw new ApiException(200, 'bad_response', 'The server sent a malformed status.');
        }
    }

    /**
     * Consumes one view.
     *
     * @return array{package: string, viewsLeft: int}
     */
    public function open(string $id): array
    {
        $result = $this->expect(200, $this->transport->send('POST', "{$this->origin}/api/secrets/{$id}/open"));

        return ['package' => $result->body, 'viewsLeft' => (int) ($result->headers->get('X-Hush-Views-Left') ?? '0')];
    }

    public function delete(string $id, string $token): void
    {
        $this->expect(204, $this->transport->send('DELETE', "{$this->origin}/api/secrets/{$id}", ['Authorization' => 'Bearer ' . $token]));
    }

    private function expect(int $status, HttpResult $result): HttpResult
    {
        if ($result->status === $status) {
            return $result;
        }
        $error = $result->json()['error'] ?? null;
        $code = is_array($error) && is_string($error['code'] ?? null) ? $error['code'] : 'http_' . $result->status;
        $message = is_array($error) && is_string($error['message'] ?? null) ? $error['message'] : sprintf('The server answered %d.', $result->status);

        throw new ApiException($result->status, $code, $message);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function field(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!is_string($value)) {
            throw new ApiException(200, 'bad_response', sprintf('The server response has no "%s".', $key));
        }

        return $value;
    }
}
