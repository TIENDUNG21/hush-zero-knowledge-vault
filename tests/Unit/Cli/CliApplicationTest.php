<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Cli;

use Hush\Cli\CliApplication;
use Hush\Client\ApiClient;
use Hush\Tests\Support\KernelTransport;
use Hush\Tests\Support\MemoryIo;
use Hush\Tests\Support\Sql;
use PHPUnit\Framework\TestCase;

/**
 * The CLI against the real kernel (in process, no sockets).
 */
final class CliApplicationTest extends TestCase
{
    private const string SERVER = 'http://hush.test';

    private KernelTransport $transport;
    private CliApplication $cli;
    private string $dir;

    protected function setUp(): void
    {
        $this->transport = new KernelTransport();
        $transport = $this->transport;
        $this->cli = CliApplication::create(static fn(string $origin): ApiClient => new ApiClient($transport, $origin));
        $this->dir = sys_get_temp_dir() . '/hush-cli-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        $files = glob($this->dir . '/*');
        foreach ($files !== false ? $files : [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    public function testSendThenGetText(): void
    {
        $send = new MemoryIo("db password: hunter2\n");
        self::assertSame(0, $this->cli->run(['send', '--server', self::SERVER, '--views', '2', '--expires', '1h'], $send), $send->stderr);
        $link = trim($send->stdout);
        self::assertMatchesRegularExpression('~\Ahttp://hush\.test/s/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}\z~', $link);
        self::assertStringContainsString('Delete link (keep it private): http://hush.test/d/', $send->stderr);

        $get = new MemoryIo();
        self::assertSame(0, $this->cli->run(['get', $link], $get), $get->stderr);
        self::assertSame("db password: hunter2\n", $get->stdout, 'stdin is sent byte for byte');
        self::assertStringContainsString('Views left: 1.', $get->stderr);
    }

    public function testTheServerOnlyEverSeesCiphertext(): void
    {
        $io = new MemoryIo('', ['HUSH_SERVER' => self::SERVER]);
        self::assertSame(0, $this->cli->run(['send', 'needle-in-plaintext'], $io));
        $key = substr(trim($io->stdout), -43);

        $stored = Sql::scalar($this->transport->fixture->pdo, 'SELECT header || meta FROM secrets');
        $chunks = Sql::scalar($this->transport->fixture->pdo, 'SELECT group_concat(data) FROM chunks');
        self::assertIsString($stored);
        self::assertIsString($chunks);
        self::assertStringNotContainsString('needle-in-plaintext', $stored . $chunks);
        self::assertStringNotContainsString($key, implode(' ', $this->transport->requests()));
    }

    public function testFilesRoundTripUnderTheirBaseName(): void
    {
        $source = $this->dir . '/source.bin';
        $data = random_bytes(3000);
        file_put_contents($source, $data);
        $send = new MemoryIo();
        self::assertSame(0, $this->cli->run(['send', '--server', self::SERVER, '--file', $source, '--type', 'application/octet-stream'], $send), $send->stderr);

        $out = $this->dir . '/received.bin';
        $get = new MemoryIo();
        self::assertSame(0, $this->cli->run(['get', trim($send->stdout), '--out', $out], $get), $get->stderr);
        self::assertSame($data, file_get_contents($out));
        self::assertStringContainsString('That was the last view', $get->stderr);
    }

    public function testWrongPasswordFailsBeforeAViewIsUsed(): void
    {
        $send = new MemoryIo("correct horse\n");
        self::assertSame(0, $this->cli->run(['send', 'launch codes', '--server', self::SERVER, '--password-stdin'], $send));
        $link = trim($send->stdout);

        $missing = new MemoryIo();
        self::assertSame(2, $this->cli->run(['get', $link], $missing));
        self::assertStringContainsString('has a password', $missing->stderr);

        $wrong = new MemoryIo("battery staple\n");
        self::assertSame(3, $this->cli->run(['get', $link, '--password-stdin'], $wrong));
        self::assertStringContainsString('does not open this secret', $wrong->stderr);
        self::assertCount(0, array_filter($this->transport->requests(), static fn(string $r): bool => str_ends_with($r, '/open')));

        $right = new MemoryIo('', ['HUSH_PW' => 'correct horse']);
        self::assertSame(0, $this->cli->run(['get', $link, '--password-env', 'HUSH_PW'], $right), $right->stderr);
        self::assertSame('launch codes', $right->stdout);
    }

    public function testSecondGetOfABurnedSecretFails(): void
    {
        $send = new MemoryIo();
        $this->cli->run(['send', 'once', '--server', self::SERVER], $send);
        $this->cli->run(['get', trim($send->stdout)], new MemoryIo());

        $again = new MemoryIo();
        self::assertSame(1, $this->cli->run(['get', trim($send->stdout)], $again));
        self::assertStringContainsString('(not_found)', $again->stderr);
    }

    public function testDeleteWithTheDeleteLink(): void
    {
        $send = new MemoryIo();
        $this->cli->run(['send', 'temporary', '--server', self::SERVER, '--json'], $send);
        $created = json_decode($send->stdout, true);
        self::assertIsArray($created);
        self::assertIsString($created['deleteLink']);
        self::assertIsString($created['link']);

        self::assertSame(0, $this->cli->run(['delete', $created['deleteLink']], new MemoryIo()));
        self::assertSame(1, $this->cli->run(['get', $created['link']], new MemoryIo()));
    }

    public function testOfflineEncryptAndDecrypt(): void
    {
        $package = $this->dir . '/note.hush';
        $encrypt = new MemoryIo("Mật khẩu \u{1F510}");
        self::assertSame(0, $this->cli->run(['encrypt', '--out', $package], $encrypt));
        $key = trim($encrypt->stdout);

        $decrypt = new MemoryIo();
        self::assertSame(0, $this->cli->run(['decrypt', $package, '--key', $key], $decrypt));
        self::assertSame("Mật khẩu \u{1F510}", $decrypt->stdout);

        $tampered = (string) file_get_contents($package);
        $tampered[100] = chr(ord($tampered[100]) ^ 1);
        file_put_contents($package, $tampered);
        self::assertSame(3, $this->cli->run(['decrypt', $package, '--key', $key], new MemoryIo()));
    }

    public function testUsageErrors(): void
    {
        $cases = [
            [['frobnicate'], 'unknown command'],
            [['send', '--server', self::SERVER, ''], 'empty'],
            [['send', 'a', 'b', '--server', self::SERVER], 'only one TEXT'],
            [['send', 'x', '--server', 'hush.example'], '--server must look like'],
            [['send', 'x', '--expires', 'soon', '--server', self::SERVER], 'Invalid duration'],
            [['get'], 'Give the share link'],
            [['get', 'https://hush.example/s/short#x'], 'Expected a link'],
            [['decrypt', 'missing.hush', '--key', 'AAAA'], 'Cannot read'],
            [['send', 'x', '--password-env', 'NOPE', '--server', self::SERVER], 'NOPE is empty or not set'],
        ];
        foreach ($cases as [$args, $message]) {
            $io = new MemoryIo();
            self::assertSame(2, $this->cli->run($args, $io), implode(' ', $args));
            self::assertStringContainsString($message, $io->stderr, implode(' ', $args));
        }
    }

    public function testHelpAndVersion(): void
    {
        $help = new MemoryIo();
        self::assertSame(0, $this->cli->run([], $help));
        self::assertStringContainsString('send', $help->stdout);

        $commandHelp = new MemoryIo();
        self::assertSame(0, $this->cli->run(['get', '--help'], $commandHelp));
        self::assertStringContainsString('Usage: hush get LINK', $commandHelp->stdout);

        $version = new MemoryIo();
        $this->cli->run(['--version'], $version);
        self::assertSame('hush 1.0.0' . PHP_EOL, $version->stdout);
    }
}
