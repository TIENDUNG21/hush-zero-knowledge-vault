<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Vault;

use Closure;
use Hush\Crypto\Package;
use Hush\Crypto\SecretOpener;
use Hush\Tests\Support\Sql;
use Hush\Tests\Support\VaultFixture;
use Hush\Vault\OpenedSecret;
use Hush\Vault\SecretId;
use Hush\Vault\Token;
use Hush\Vault\VaultException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class VaultServiceTest extends TestCase
{
    private VaultFixture $fx;

    protected function setUp(): void
    {
        $this->fx = new VaultFixture();
    }

    public function testCreateReturnsIdTokenAndDeadlines(): void
    {
        $sealed = VaultFixture::sealText();
        $created = $this->fx->vault->create($sealed->headerBytes, $sealed->metaRecord, 3600, 1);

        self::assertTrue(SecretId::isValid($created->id));
        self::assertMatchesRegularExpression('/\A' . Token::PATTERN . '\z/', $created->deletionToken);
        self::assertSame($this->fx->clock->timestamp() + 3600, $created->expiresAt);
        self::assertSame($this->fx->clock->timestamp() + 900, $created->uploadDeadline);
        self::assertSame(1, $created->chunkCount);
        self::assertNotSame(
            $created->deletionToken,
            Sql::scalar($this->fx->pdo, 'SELECT owner_token FROM secrets WHERE id = ?', [$created->id]),
            'only the hash of the token is stored',
        );
    }

    /**
     * @return iterable<string, array{Closure(string, string): array{string, string, int, int}, string}>
     */
    public static function invalidCreations(): iterable
    {
        yield 'garbage header' => [static fn(string $h, string $m): array => ['nope', $m, 3600, 1], 'invalid_header'];
        yield 'meta too short' => [static fn(string $h, string $m): array => [$h, substr($m, 0, 100), 3600, 1], 'invalid_meta'];
        yield 'meta not a block' => [static fn(string $h, string $m): array => [$h, $m . 'x', 3600, 1], 'invalid_meta'];
        yield 'ttl too short' => [static fn(string $h, string $m): array => [$h, $m, 59, 1], 'invalid_expiry'];
        yield 'ttl too long' => [static fn(string $h, string $m): array => [$h, $m, 604801, 1], 'invalid_expiry'];
        yield 'zero views' => [static fn(string $h, string $m): array => [$h, $m, 3600, 0], 'invalid_views'];
        yield 'too many views' => [static fn(string $h, string $m): array => [$h, $m, 3600, 101], 'invalid_views'];
    }

    /**
     * @param Closure(string, string): array{string, string, int, int} $mutate
     */
    #[DataProvider('invalidCreations')]
    public function testCreateRejectsInvalidInput(Closure $mutate, string $code): void
    {
        $sealed = VaultFixture::sealText();
        [$header, $meta, $ttl, $views] = $mutate($sealed->headerBytes, $sealed->metaRecord);

        $this->assertVaultError($code, fn() => $this->fx->vault->create($header, $meta, $ttl, $views));
    }

    public function testCreateRejectsEnvelopesLargerThanTheServerLimit(): void
    {
        $sealed = VaultFixture::sealFile(70 * 1024, 4096); // limit in the fixture is 64 KiB

        $this->assertVaultError('secret_too_large', fn() => $this->fx->vault->create($sealed->headerBytes, $sealed->metaRecord, 3600, 1));
    }

    public function testFullLifecycleReturnsTheSameCiphertext(): void
    {
        $sealed = VaultFixture::sealFile(2500);
        [$id] = $this->fx->store($sealed, maxViews: 2);

        $status = $this->fx->vault->status($id);
        self::assertFalse($status->passwordProtected);
        self::assertSame(2, $status->viewsLeft);
        self::assertSame(3, $status->chunkCount);

        $opened = $this->fx->vault->open($id);
        $bytes = $this->drain($opened);
        self::assertSame(1, $opened->viewsLeft);
        self::assertSame($opened->packageLength, strlen($bytes));
        $package = Package::unpack($bytes);
        self::assertSame($sealed->headerBytes, $package->headerBytes);
        self::assertSame($sealed->metaRecord, $package->meta);
        self::assertSame(2500, strlen(SecretOpener::open($package, $sealed->fragmentKey)->data));
    }

    public function testLastViewBurnsAndPurges(): void
    {
        [$id] = $this->fx->store(VaultFixture::sealText(), maxViews: 1);

        $opened = $this->fx->vault->open($id);
        self::assertSame(0, $opened->viewsLeft);
        self::assertNotSame('', $this->drain($opened));

        self::assertSame(0, Sql::scalar($this->fx->pdo, 'SELECT COUNT(*) FROM secrets'));
        self::assertSame(0, Sql::scalar($this->fx->pdo, 'SELECT COUNT(*) FROM chunks'));
        $this->assertVaultError('not_found', fn() => $this->fx->vault->open($id));
        $this->assertVaultError('not_found', fn() => $this->fx->vault->status($id));
    }

    public function testBurnedRowIsUnreadableEvenBeforeTheStreamFinishes(): void
    {
        [$id] = $this->fx->store(VaultFixture::sealText(), maxViews: 1);

        $this->fx->vault->open($id); // stream never consumed (client disconnected)

        self::assertSame('burned', Sql::scalar($this->fx->pdo, 'SELECT state FROM secrets WHERE id = ?', [$id]));
        $this->assertVaultError('not_found', fn() => $this->fx->vault->open($id));
    }

    public function testOnlyOneOfTwoConnectionsWinsALastView(): void
    {
        $path = sys_get_temp_dir() . '/hush-race-' . bin2hex(random_bytes(4)) . '.sqlite';
        $a = new VaultFixture($path);
        $b = new VaultFixture($path);
        [$id] = $a->store(VaultFixture::sealText(), maxViews: 1);

        $winners = 0;
        foreach ([$a, $b] as $fixture) {
            try {
                $fixture->vault->open($id);
                $winners++;
            } catch (VaultException) {
            }
        }

        self::assertSame(1, $winners);
        unset($a, $b);
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($path . $suffix);
        }
    }

    public function testExpiredSecretsCannotBeReadOrDeleted(): void
    {
        [$id, $token] = $this->fx->store(VaultFixture::sealText(), maxViews: 5, ttl: 60);

        $this->fx->clock->advance(60);

        $this->assertVaultError('not_found', fn() => $this->fx->vault->status($id));
        $this->assertVaultError('not_found', fn() => $this->fx->vault->open($id));
        $this->assertVaultError('not_found', fn() => $this->fx->vault->delete($id, $token));
    }

    public function testUnsealedSecretsAreNotReadable(): void
    {
        $sealed = VaultFixture::sealText();
        $created = $this->fx->vault->create($sealed->headerBytes, $sealed->metaRecord, 3600, 1);

        $this->assertVaultError('not_found', fn() => $this->fx->vault->open($created->id));
    }

    public function testChunkUploadRules(): void
    {
        $sealed = VaultFixture::sealFile(2500);
        $created = $this->fx->vault->create($sealed->headerBytes, $sealed->metaRecord, 3600, 1);
        $id = $created->id;
        $token = $created->deletionToken;

        $this->assertVaultError('invalid_token', fn() => $this->fx->vault->putChunk($id, 0, Token::generate(), $sealed->chunkRecord(0)));
        $this->assertVaultError('chunk_index_out_of_range', fn() => $this->fx->vault->putChunk($id, 3, $token, $sealed->chunkRecord(2)));
        $this->assertVaultError('invalid_chunk_length', fn() => $this->fx->vault->putChunk($id, 0, $token, $sealed->chunkRecord(2)));
        $this->assertVaultError('invalid_chunk_length', fn() => $this->fx->vault->putChunk($id, 2, $token, $sealed->chunkRecord(2) . 'x'));
        $this->assertVaultError('missing_chunks', fn() => $this->fx->vault->seal($id, $token));

        $this->fx->vault->putChunk($id, 0, $token, $sealed->chunkRecord(0));
        $this->fx->vault->putChunk($id, 0, $token, $sealed->chunkRecord(0)); // retry overwrites
        $this->fx->vault->putChunk($id, 1, $token, $sealed->chunkRecord(1));
        $this->fx->vault->putChunk($id, 2, $token, $sealed->chunkRecord(2));
        $this->fx->vault->seal($id, $token);

        $this->assertVaultError('already_sealed', fn() => $this->fx->vault->putChunk($id, 0, $token, $sealed->chunkRecord(0)));
        $this->assertVaultError('already_sealed', fn() => $this->fx->vault->seal($id, $token));
    }

    public function testUploadWindowCloses(): void
    {
        $sealed = VaultFixture::sealText();
        $created = $this->fx->vault->create($sealed->headerBytes, $sealed->metaRecord, 3600, 1);

        $this->fx->clock->advance(900);

        $this->assertVaultError('upload_window_closed', fn() => $this->fx->vault->putChunk($created->id, 0, $created->deletionToken, $sealed->chunkRecord(0)));
    }

    public function testDeleteNeedsTheToken(): void
    {
        [$id, $token] = $this->fx->store(VaultFixture::sealText(), maxViews: 3);

        $this->assertVaultError('invalid_token', fn() => $this->fx->vault->delete($id, Token::generate()));
        $this->fx->vault->delete($id, $token);

        $this->assertVaultError('not_found', fn() => $this->fx->vault->status($id));
        self::assertSame(0, Sql::scalar($this->fx->pdo, 'SELECT COUNT(*) FROM chunks'));
    }

    public function testGarbageCollection(): void
    {
        [$expired] = $this->fx->store(VaultFixture::sealText(), ttl: 60);
        $abandoned = VaultFixture::sealText();
        $this->fx->vault->create($abandoned->headerBytes, $abandoned->metaRecord, 7200, 1);
        [$burned] = $this->fx->store(VaultFixture::sealText(), ttl: 7200);
        $this->fx->vault->open($burned); // never drained: row stays burned
        [$alive] = $this->fx->store(VaultFixture::sealText(), ttl: 7200);

        $this->fx->clock->advance(1000);
        $report = $this->fx->vault->collectGarbage();

        self::assertSame(['expired' => 1, 'abandoned' => 1, 'burned' => 1], $report);
        self::assertSame([$alive], Sql::column($this->fx->pdo, 'SELECT id FROM secrets'));
        self::assertNotSame($expired, $alive);
    }

    public function testStatusReportsPasswordProtection(): void
    {
        [$id] = $this->fx->store(VaultFixture::sealText('x', 'pw'));

        self::assertTrue($this->fx->vault->status($id)->passwordProtected);
    }

    private function drain(OpenedSecret $opened): string
    {
        $out = '';
        foreach ($opened->package as $piece) {
            $out .= $piece;
        }

        return $out;
    }

    /**
     * @param Closure(): mixed $action
     */
    private function assertVaultError(string $code, Closure $action): void
    {
        try {
            $action();
            self::fail(sprintf('expected %s', $code));
        } catch (VaultException $e) {
            self::assertSame($code, $e->errorCode, $e->getMessage());
        }
    }
}
