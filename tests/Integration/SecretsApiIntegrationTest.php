<?php

declare(strict_types=1);

namespace Hush\Tests\Integration;

use Hush\Crypto\Package;
use Hush\Crypto\PlainSecret;
use Hush\Crypto\SecretOpener;
use Hush\Crypto\SecretSealer;
use Hush\Support\Base64Url;
use Hush\Tests\Support\Sql;
use Hush\Tests\Support\VaultFixture;

final class SecretsApiIntegrationTest extends IntegrationTestCase
{
    protected static function port(): int
    {
        return 5141;
    }

    public function testHealth(): void
    {
        $result = $this->request('GET', '/healthz');

        self::assertSame(200, $result->status);
        self::assertSame(['status' => 'ok'], $result->json());
    }

    public function testFullRoundTripThroughHttp(): void
    {
        $sealed = VaultFixture::sealFile(3000);
        [$id] = $this->storeSecret($sealed, maxViews: 2);

        $status = $this->request('GET', '/api/secrets/' . $id);
        self::assertSame(200, $status->status);
        self::assertFalse($status->json()['passwordProtected']);
        self::assertSame(2, $status->json()['viewsLeft']);
        self::assertSame(3, $status->json()['chunkCount']);
        self::assertSame(Base64Url::encode($sealed->headerBytes), $status->json()['header']);
        self::assertSame(Base64Url::encode($sealed->metaRecord), $status->json()['meta']);

        $opened = $this->request('POST', "/api/secrets/{$id}/open");
        self::assertSame(200, $opened->status);
        self::assertSame('application/octet-stream', $opened->headers->get('Content-Type'));
        self::assertSame('1', $opened->headers->get('X-Hush-Views-Left'));
        self::assertSame((string) strlen($opened->body), $opened->headers->get('Content-Length'));

        $plain = SecretOpener::open(Package::unpack($opened->body), $sealed->fragmentKey);
        self::assertSame(3000, strlen($plain->data));
        self::assertSame('data.bin', $plain->name);

        self::assertSame(200, $this->request('POST', "/api/secrets/{$id}/open")->status);
        $gone = $this->request('POST', "/api/secrets/{$id}/open");
        self::assertSame(404, $gone->status);
        self::assertSame('not_found', $this->errorCode($gone));
        self::assertSame(0, Sql::scalar($this->database(), 'SELECT COUNT(*) FROM secrets WHERE id = ?', [$id]), 'purged after the last view');
    }

    public function testLargeFileTravelsInDefaultSizedChunks(): void
    {
        $data = random_bytes(1_200_000);
        $sealed = SecretSealer::seal(PlainSecret::file($data, 'backup.tar.gz', 'application/gzip'));
        self::assertSame(524_288, $sealed->header->chunkSize);
        self::assertSame(3, $sealed->header->chunkCount);
        [$id] = $this->storeSecret($sealed);

        $opened = $this->request('POST', "/api/secrets/{$id}/open");

        self::assertSame(200, $opened->status);
        $plain = SecretOpener::open(Package::unpack($opened->body), $sealed->fragmentKey);
        self::assertSame(hash('sha256', $data), hash('sha256', $plain->data));
        self::assertSame('backup.tar.gz', $plain->name);
    }

    public function testStatusDoesNotConsumeViews(): void
    {
        [$id] = $this->storeSecret(VaultFixture::sealText(), maxViews: 1);

        for ($i = 0; $i < 3; $i++) {
            self::assertSame(200, $this->request('GET', '/api/secrets/' . $id)->status);
            self::assertSame(200, $this->request('HEAD', '/api/secrets/' . $id)->status);
        }
        self::assertSame(200, $this->request('POST', "/api/secrets/{$id}/open")->status);
    }

    public function testDeleteNeedsTheRightToken(): void
    {
        [$id, $token] = $this->storeSecret(VaultFixture::sealText(), maxViews: 3);

        $missing = $this->request('DELETE', '/api/secrets/' . $id);
        self::assertSame(401, $missing->status);
        self::assertSame('Bearer', $missing->headers->get('WWW-Authenticate'));

        $wrong = $this->request('DELETE', '/api/secrets/' . $id, ['Authorization' => 'Bearer ' . str_repeat('A', 43)]);
        self::assertSame(403, $wrong->status);

        self::assertSame(204, $this->request('DELETE', '/api/secrets/' . $id, ['Authorization' => 'Bearer ' . $token])->status);
        self::assertSame(404, $this->request('GET', '/api/secrets/' . $id)->status);
    }

    public function testUnsealedSecretIsNotReadable(): void
    {
        $sealed = VaultFixture::sealText();
        $created = $this->postJson('/api/secrets', [
            'header' => Base64Url::encode($sealed->headerBytes),
            'meta' => Base64Url::encode($sealed->metaRecord),
            'expiresIn' => 600,
            'maxViews' => 1,
        ]);
        $id = $created->json()['id'] ?? null;
        $token = $created->json()['deletionToken'] ?? null;
        self::assertIsString($id);
        self::assertIsString($token);

        self::assertSame(404, $this->request('POST', "/api/secrets/{$id}/open")->status);
        $seal = $this->request('POST', "/api/secrets/{$id}/seal", ['Authorization' => 'Bearer ' . $token]);
        self::assertSame(409, $seal->status);
        self::assertSame('missing_chunks', $this->errorCode($seal));
    }

    public function testExpiredSecretIsGone(): void
    {
        [$id] = $this->storeSecret(VaultFixture::sealText(), maxViews: 5);
        Sql::exec($this->database(), 'UPDATE secrets SET expires_at = ? WHERE id = ?', [time() - 1, $id]);

        self::assertSame(404, $this->request('GET', '/api/secrets/' . $id)->status);
        self::assertSame(404, $this->request('POST', "/api/secrets/{$id}/open")->status);
    }

    public function testMalformedRequestsGetPreciseErrors(): void
    {
        $sealed = VaultFixture::sealText();
        $valid = [
            'header' => Base64Url::encode($sealed->headerBytes),
            'meta' => Base64Url::encode($sealed->metaRecord),
            'expiresIn' => 600,
            'maxViews' => 1,
        ];

        $badJson = $this->request('POST', '/api/secrets', ['Content-Type' => 'application/json'], '{"header":');
        self::assertSame(400, $badJson->status);
        self::assertSame('invalid_json', $this->errorCode($badJson));

        $list = $this->request('POST', '/api/secrets', ['Content-Type' => 'application/json'], '[1,2]');
        self::assertSame(400, $list->status);

        $wrongType = $this->request('POST', '/api/secrets', ['Content-Type' => 'text/plain'], (string) json_encode($valid));
        self::assertSame(415, $wrongType->status);

        $badHeader = $this->postJson('/api/secrets', ['header' => Base64Url::encode('HUSX' . str_repeat("\0", 32))] + $valid);
        self::assertSame(422, $badHeader->status);
        self::assertSame('invalid_header', $this->errorCode($badHeader));

        $padded = $this->postJson('/api/secrets', ['meta' => base64_encode($sealed->metaRecord)] + $valid);
        self::assertSame(422, $padded->status);

        $stringViews = $this->postJson('/api/secrets', ['maxViews' => '1'] + $valid);
        self::assertSame(422, $stringViews->status);
        self::assertSame('invalid_field', $this->errorCode($stringViews));

        $views = $this->postJson('/api/secrets', ['maxViews' => 1000] + $valid);
        self::assertSame('invalid_views', $this->errorCode($views));
    }

    public function testUnknownRoutesAndMethods(): void
    {
        self::assertSame(404, $this->request('GET', '/api/secrets/short')->status);
        self::assertSame(404, $this->request('GET', '/api/secrets/' . str_repeat('A', 22) . '/../../etc')->status);
        $wrong = $this->request('PATCH', '/api/secrets');
        self::assertSame(405, $wrong->status);
        self::assertSame('POST', $wrong->headers->get('Allow'));
    }

    public function testNoPhpVersionLeaks(): void
    {
        self::assertNull($this->request('GET', '/healthz')->headers->get('X-Powered-By'));
    }
}
