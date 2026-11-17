<?php

declare(strict_types=1);

namespace Hush\Tests\Support;

use Hush\Client\HttpResult;
use Hush\Client\HttpTransport;
use Hush\Config\Config;
use Hush\Http\HeaderBag;
use Hush\Http\Request;
use Hush\Kernel\Application;
use Hush\Kernel\HttpKernel;
use Hush\Support\Clock;
use Hush\Support\Logger;
use PDO;

/**
 * Sends client requests straight into an in-process kernel, so CLI tests
 * run against the real server code without sockets.
 */
final class KernelTransport implements HttpTransport
{
    public readonly HttpKernel $kernel;
    public readonly VaultFixture $fixture;

    /** @var list<string> "METHOD path" of every request */
    private array $log = [];

    public function __construct()
    {
        $this->fixture = new VaultFixture();
        $config = new Config(dirname(__DIR__, 2), ':memory:');
        $this->kernel = (new Application($config, [
            PDO::class => $this->fixture->pdo,
            Clock::class => $this->fixture->clock,
            Logger::class => new MemoryLogger(),
        ]))->kernel();
    }

    public function send(string $method, string $url, array $headers = [], string $body = ''): HttpResult
    {
        $path = (string) parse_url($url, PHP_URL_PATH);
        $this->log[] = $method . ' ' . $path;
        if ($body !== '' || in_array($method, ['POST', 'PUT'], true)) {
            $headers['Content-Length'] = (string) strlen($body);
        }
        $response = $this->kernel->handle(new Request($method, $path, [], new HeaderBag($headers), ['REMOTE_ADDR' => '127.0.0.1'], $body));

        return new HttpResult($response->status(), $response->headers(), $response->bodyString());
    }

    /**
     * @return list<string>
     */
    public function requests(): array
    {
        return $this->log;
    }
}
