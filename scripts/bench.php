<?php

declare(strict_types=1);

/*
 * Measures the PHP side: key derivation, envelope throughput and full HTTP
 * round trips against php -S (with opcache, as in the Docker image).
 * Prints a Markdown table.
 *
 *   php scripts/bench.php
 *
 * Uses port 5149 for its own server and a temporary database.
 */

use Hush\Client\ApiClient;
use Hush\Client\HttpResult;
use Hush\Client\HttpTransport;
use Hush\Client\StreamTransport;
use Hush\Crypto\Format;
use Hush\Crypto\Header;
use Hush\Crypto\KeySchedule;
use Hush\Crypto\Package;
use Hush\Crypto\PlainSecret;
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretOpener;
use Hush\Crypto\SecretSealer;
use Hush\Http\HeaderBag;
use Hush\Storage\Database;
use Hush\Storage\Migrator;

require dirname(__DIR__) . '/vendor/autoload.php';

const PORT = 5149;

/**
 * @param Closure(): mixed $work
 *
 * @return float median milliseconds
 */
function median(int $runs, Closure $work): float
{
    $times = [];
    for ($i = 0; $i < $runs; $i++) {
        $start = hrtime(true);
        $work();
        $times[] = (hrtime(true) - $start) / 1e6;
    }
    sort($times);

    return $times[intdiv(count($times), 2)];
}

$rows = [];

$header = new Header(true, Format::DEFAULT_ITERATIONS, random_bytes(16), 1024, 1);
$rows[] = ['PBKDF2-SHA256, 600,000 iterations + HKDF', sprintf('%.0f ms', median(5, static fn() => KeySchedule::contentKey(random_bytes(32), $header, 'correct horse battery staple')))];

$data = random_bytes(32 * 1_048_576);
$secret = PlainSecret::file($data, 'bench.bin');
$sealedMs = median(5, static fn() => SecretSealer::seal($secret)->toPackage());
$sealed = SecretSealer::seal($secret);
$package = $sealed->toPackage();
$openMs = median(5, static fn() => SecretOpener::open($package, $sealed->fragmentKey));
$rows[] = ['Seal 32 MiB (64 chunks of 512 KiB)', sprintf('%.0f ms (%.0f MiB/s)', $sealedMs, 32 / ($sealedMs / 1000))];
$rows[] = ['Open 32 MiB', sprintf('%.0f ms (%.0f MiB/s)', $openMs, 32 / ($openMs / 1000))];

// HTTP round trips through the real front controller.
$dir = sys_get_temp_dir() . '/hush-bench-' . bin2hex(random_bytes(4));
mkdir($dir);
$env = getenv();
$env['HUSH_DB_PATH'] = $dir . '/hush.sqlite';
$env['HUSH_RATE_CREATE'] = '100000,1000';
$env['HUSH_RATE_READ'] = '100000,1000';
$env['HUSH_RATE_CHUNK'] = '100000,1000';
(new Migrator(Database::connect($env['HUSH_DB_PATH']), dirname(__DIR__) . '/migrations'))->migrate();
// Production runs with opcache; without it php -S recompiles every class per request.
$opcache = extension_loaded('Zend OPcache') ? [] : ['-d', 'zend_extension=opcache'];
$server = proc_open(
    [PHP_BINARY, ...$opcache, '-d', 'opcache.enable_cli=1', '-S', '127.0.0.1:' . PORT, 'public/index.php'],
    [0 => ['file', $dir . '/stdin', 'w'], 1 => ['file', $dir . '/log', 'w'], 2 => ['file', $dir . '/log', 'w']],
    $pipes,
    dirname(__DIR__),
    $env,
);
if (!is_resource($server)) {
    fwrite(STDERR, "could not start php -S\n");
    exit(1);
}
usleep(500_000);

// ext-curl stops reading at Content-Length. PHP's stream wrapper (used by
// bin/hush) waits for the server to close the socket, which php -S on
// Windows does late (~10 ms), so curl isolates the server's own cost.
$transport = extension_loaded('curl') ? new class implements HttpTransport {
    public function send(string $method, string $url, array $headers = [], string $body = ''): HttpResult
    {
        if ($method === '') {
            throw new InvalidArgumentException('empty HTTP method');
        }
        $curl = curl_init($url);
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        $responseHeaders = new HeaderBag();
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADERFUNCTION => static function (CurlHandle $handle, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $responseHeaders = $responseHeaders->withAdded(trim($parts[0]), trim($parts[1]));
                }

                return strlen($line);
            },
        ]);
        if ($body !== '' || $method === 'POST' || $method === 'PUT') {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        $result = curl_exec($curl);

        return new HttpResult(curl_getinfo($curl, CURLINFO_RESPONSE_CODE), $responseHeaders, is_string($result) ? $result : '');
    }
} : new StreamTransport();
$client = new ApiClient($transport, 'http://127.0.0.1:' . PORT);
$roundTrip = static function (PlainSecret $secret) use ($client): void {
    $sealed = SecretSealer::seal($secret, new SealOptions());
    $created = $client->upload($sealed, 600, 1);
    $client->status($created['id']);
    $opened = $client->open($created['id']);
    SecretOpener::open(Package::unpack($opened['package']), $sealed->fragmentKey);
};

$text = PlainSecret::text(str_repeat('s', 200));
$roundTrip($text); // warm-up
$rows[] = ['HTTP round trip, 200-byte text (create, chunk, seal, status, open)', sprintf('%.1f ms', median(30, static fn() => $roundTrip($text)))];
$file = PlainSecret::file(random_bytes(8 * 1_048_576), 'bench.bin');
$rows[] = ['HTTP round trip, 8 MiB file (16 chunks)', sprintf('%.0f ms', median(5, static fn() => $roundTrip($file)))];

proc_terminate($server);
proc_close($server);

$clientName = $transport instanceof StreamTransport ? 'stream wrapper' : 'ext-curl';
echo '| Operation (PHP ' . PHP_VERSION . ", OpenSSL; HTTP client {$clientName}) | Median |\n|---|---|\n";
foreach ($rows as [$name, $value]) {
    echo "| {$name} | {$value} |\n";
}
