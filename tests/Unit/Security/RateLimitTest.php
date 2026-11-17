<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Security;

use Hush\Config\Config;
use Hush\Http\HeaderBag;
use Hush\Http\Request;
use Hush\Security\ClientIp;
use Hush\Security\RateLimiter;
use Hush\Security\RateRule;
use Hush\Security\TokenBucket;
use Hush\Tests\Support\FrozenClock;
use Hush\Tests\Support\Sql;
use Hush\Tests\Support\VaultFixture;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class RateLimitTest extends TestCase
{
    public function testNewBucketStartsFull(): void
    {
        $decision = TokenBucket::take(new RateRule(3, 1), null, null, 100.0);

        self::assertTrue($decision->allowed);
        self::assertSame(2, $decision->remaining());
    }

    public function testEmptyBucketDeniesWithRetryAfter(): void
    {
        $decision = TokenBucket::take(new RateRule(3, 0.25), 0.5, 100.0, 100.0);

        self::assertFalse($decision->allowed);
        self::assertSame(2, $decision->retryAfterSeconds, '0.5 missing tokens at 0.25/s');
    }

    public function testRefillIsCappedAtCapacity(): void
    {
        $decision = TokenBucket::take(new RateRule(3, 1), 0.0, 0.0, 1_000_000.0);

        self::assertTrue($decision->allowed);
        self::assertSame(2, $decision->remaining());
    }

    public function testClockGoingBackwardsAddsNothing(): void
    {
        $decision = TokenBucket::take(new RateRule(3, 1), 0.2, 200.0, 100.0);

        self::assertFalse($decision->allowed);
    }

    public function testRuleParsing(): void
    {
        self::assertEquals(new RateRule(30, 0.05), RateRule::parse('30,0.05'));
        $this->expectException(InvalidArgumentException::class);
        RateRule::parse('0,1');
    }

    public function testLimiterPersistsBucketsAndRefills(): void
    {
        $fixture = new VaultFixture();
        $clock = new FrozenClock();
        $config = new Config('/srv', ':memory:', rateRules: ['create' => new RateRule(2, 0.5)]);
        $limiter = new RateLimiter($fixture->pdo, $config, $clock);

        self::assertTrue($limiter->hit('create', 'v4:203.0.113.5')->allowed);
        self::assertTrue($limiter->hit('create', 'v4:203.0.113.5')->allowed);
        $denied = $limiter->hit('create', 'v4:203.0.113.5');
        self::assertFalse($denied->allowed);
        self::assertSame(2, $denied->retryAfterSeconds);
        self::assertTrue($limiter->hit('create', 'v4:198.51.100.7')->allowed, 'other clients have their own bucket');

        $clock->advance(2.0);
        self::assertTrue($limiter->hit('create', 'v4:203.0.113.5')->allowed);
    }

    public function testBucketsDoNotStoreReadableAddresses(): void
    {
        $fixture = new VaultFixture();
        $limiter = new RateLimiter($fixture->pdo, new Config('/srv', ':memory:'), new FrozenClock());

        $limiter->hit('read', 'v4:203.0.113.5');

        $keys = Sql::column($fixture->pdo, 'SELECT bucket FROM rate_buckets');
        self::assertCount(1, $keys);
        self::assertIsString($keys[0]);
        self::assertStringStartsWith('read:', $keys[0]);
        self::assertStringNotContainsString('203.0.113', $keys[0]);
    }

    public function testPruneRemovesRefilledBuckets(): void
    {
        $fixture = new VaultFixture();
        $clock = new FrozenClock();
        $limiter = new RateLimiter($fixture->pdo, new Config('/srv', ':memory:', rateRules: ['read' => new RateRule(10, 1)]), $clock);
        $limiter->hit('read', 'a');
        $clock->advance(5);
        $limiter->hit('read', 'b');

        $clock->advance(6); // "a" idle 11 s >= 10 s to refill; "b" idle 6 s
        self::assertSame(1, $limiter->prune());
        self::assertSame(1, Sql::scalar($fixture->pdo, 'SELECT COUNT(*) FROM rate_buckets'));
    }

    public function testUnknownBucketIsAProgrammingError(): void
    {
        $limiter = new RateLimiter((new VaultFixture())->pdo, new Config('/srv', ':memory:'), new FrozenClock());

        $this->expectException(InvalidArgumentException::class);
        $limiter->hit('nope', 'x');
    }

    public function testClientIpUsesThePeerUnlessItIsATrustedProxy(): void
    {
        $direct = new Request('GET', '/', [], new HeaderBag(['X-Forwarded-For' => '1.2.3.4']), ['REMOTE_ADDR' => '203.0.113.9']);
        self::assertSame('203.0.113.9', ClientIp::resolve($direct, []), 'spoofed XFF is ignored');

        $proxied = new Request('GET', '/', [], new HeaderBag(['X-Forwarded-For' => '1.2.3.4, 198.51.100.1, 10.0.0.2']), ['REMOTE_ADDR' => '10.0.0.1']);
        self::assertSame('198.51.100.1', ClientIp::resolve($proxied, ['10.0.0.1', '10.0.0.2']));

        $garbage = new Request('GET', '/', [], new HeaderBag(['X-Forwarded-For' => 'not-an-ip']), ['REMOTE_ADDR' => '10.0.0.1']);
        self::assertSame('10.0.0.1', ClientIp::resolve($garbage, ['10.0.0.1']));
    }

    public function testBucketKeysGroupIpv6By64(): void
    {
        self::assertSame('v4:203.0.113.9', ClientIp::bucketKey('203.0.113.9'));
        self::assertSame('v4:203.0.113.9', ClientIp::bucketKey('::ffff:203.0.113.9'));
        self::assertSame(ClientIp::bucketKey('2001:db8:1:2::1'), ClientIp::bucketKey('2001:db8:1:2:ffff::9'));
        self::assertNotSame(ClientIp::bucketKey('2001:db8:1:2::1'), ClientIp::bucketKey('2001:db8:1:3::1'));
        self::assertSame('invalid', ClientIp::bucketKey('garbage'));
    }
}
