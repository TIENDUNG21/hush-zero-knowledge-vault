<?php

declare(strict_types=1);

namespace Hush\Tests\Interop;

use Hush\Tests\Integration\ServerProcess;
use PHPUnit\Framework\TestCase;

/**
 * The PHP CLI and the browser modules (under Node) talk to the same real
 * server: whatever one sends, the other receives.
 */
final class HttpInteropTest extends TestCase
{
    private static ?ServerProcess $server = null;

    public static function setUpBeforeClass(): void
    {
        self::$server = new ServerProcess(5145);
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop();
        self::$server = null;
    }

    public function testCliSendsBrowserCodeReceives(): void
    {
        $text = "API_TOKEN=hush_9f8e7d6c \u{1F510}\n";
        [$code, $stdout, $stderr] = Node::run([PHP_BINARY, 'bin/hush', 'send', '--server', $this->origin()], $text);
        self::assertSame(0, $code, $stderr);

        $result = Node::call('get', trim($stdout), []);

        self::assertIsArray($result['opened']);
        self::assertSame($text, $result['opened']['text']);
    }

    public function testBrowserCodeSendsCliReceivesWithPassword(): void
    {
        $result = Node::call('send', $this->origin(), [
            'secret' => ['kind' => 'text', 'text' => 'ssh-ed25519 AAAAC3Nza hush@laptop'],
            'password' => 'Mật khẩu',
        ]);
        self::assertIsString($result['link']);

        [$wrongCode, , $wrongErr] = Node::run([PHP_BINARY, 'bin/hush', 'get', $result['link'], '--password-stdin'], "nope\n");
        self::assertSame(3, $wrongCode, $wrongErr);

        [$code, $stdout, $stderr] = Node::run([PHP_BINARY, 'bin/hush', 'get', $result['link'], '--password-stdin'], "Mật khẩu\n");
        self::assertSame(0, $code, $stderr);
        self::assertSame('ssh-ed25519 AAAAC3Nza hush@laptop', $stdout);
    }

    public function testFilesCrossInBothDirections(): void
    {
        $dir = sys_get_temp_dir() . '/hush-http-interop-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $source = $dir . '/scan.png';
        $data = random_bytes(700_000);
        file_put_contents($source, $data);

        [$code, $stdout, $stderr] = Node::run([PHP_BINARY, 'bin/hush', 'send', '--server', $this->origin(), '--file', $source, '--type', 'image/png']);
        self::assertSame(0, $code, $stderr);
        $fromCli = Node::call('get', trim($stdout), []);
        self::assertIsArray($fromCli['opened']);
        self::assertSame(['scan.png', 'image/png', hash('sha256', $data)], [$fromCli['opened']['name'], $fromCli['opened']['type'], $fromCli['opened']['sha256']]);

        $sent = Node::call('send', $this->origin(), ['secret' => ['kind' => 'file', 'dataBase64' => base64_encode($data), 'name' => 'scan.png', 'type' => 'image/png']]);
        self::assertIsString($sent['link']);
        $out = $dir . '/received.png';
        [$getCode, , $getErr] = Node::run([PHP_BINARY, 'bin/hush', 'get', $sent['link'], '--out', $out]);
        self::assertSame(0, $getCode, $getErr);
        self::assertSame($data, file_get_contents($out));

        unlink($source);
        unlink($out);
        rmdir($dir);
    }

    private function origin(): string
    {
        self::assertNotNull(self::$server);

        return self::$server->baseUrl;
    }
}
