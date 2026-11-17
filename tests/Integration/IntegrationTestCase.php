<?php

declare(strict_types=1);

namespace Hush\Tests\Integration;

use Hush\Client\HttpResult;
use Hush\Client\StreamTransport;
use Hush\Crypto\SealedSecret;
use Hush\Storage\Database;
use Hush\Support\Base64Url;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * One php -S server per test class, on a port from the 5141-5144 range.
 */
abstract class IntegrationTestCase extends TestCase
{
    protected static ?ServerProcess $server = null;

    abstract protected static function port(): int;

    /**
     * @return array<string, string>
     */
    protected static function environment(): array
    {
        return [];
    }

    public static function setUpBeforeClass(): void
    {
        static::$server = new ServerProcess(static::port(), static::environment());
    }

    public static function tearDownAfterClass(): void
    {
        static::$server?->stop();
        static::$server = null;
    }

    protected function server(): ServerProcess
    {
        self::assertNotNull(static::$server);

        return static::$server;
    }

    /**
     * @param array<string, string> $headers
     */
    protected function request(string $method, string $path, array $headers = [], string $body = ''): HttpResult
    {
        return (new StreamTransport(10.0))->send($method, $this->server()->baseUrl . $path, $headers, $body);
    }

    /**
     * @param array<string, mixed> $data
     */
    protected function postJson(string $path, array $data): HttpResult
    {
        return $this->request('POST', $path, ['Content-Type' => 'application/json'], json_encode($data, JSON_THROW_ON_ERROR));
    }

    /**
     * Creates, uploads and seals; returns [id, token].
     *
     * @return array{string, string}
     */
    protected function storeSecret(SealedSecret $sealed, int $maxViews = 1, int $ttl = 3600): array
    {
        $created = $this->postJson('/api/secrets', [
            'header' => Base64Url::encode($sealed->headerBytes),
            'meta' => Base64Url::encode($sealed->metaRecord),
            'expiresIn' => $ttl,
            'maxViews' => $maxViews,
        ]);
        self::assertSame(201, $created->status, $created->body);
        $id = $created->json()['id'] ?? null;
        $token = $created->json()['deletionToken'] ?? null;
        self::assertIsString($id);
        self::assertIsString($token);

        foreach ($sealed->chunkRecords() as $index => $record) {
            $put = $this->request('PUT', "/api/secrets/{$id}/chunks/{$index}", [
                'Content-Type' => 'application/octet-stream',
                'Authorization' => 'Bearer ' . $token,
            ], $record);
            self::assertSame(204, $put->status, $put->body);
        }
        $seal = $this->request('POST', "/api/secrets/{$id}/seal", ['Authorization' => 'Bearer ' . $token]);
        self::assertSame(200, $seal->status, $seal->body);

        return [$id, $token];
    }

    protected function database(): PDO
    {
        return Database::connect($this->server()->databasePath);
    }

    protected function errorCode(HttpResult $result): ?string
    {
        $error = $result->json()['error'] ?? null;

        return is_array($error) && is_string($error['code'] ?? null) ? $error['code'] : null;
    }
}
