<?php

declare(strict_types=1);

/*
 * Helper process for VaultConcurrencyTest: waits until a shared start time,
 * then tries to open one secret and prints "won" or "lost".
 * Usage: php race-open.php <database> <secret-id> <start-at-unix-float>
 */

use Hush\Config\Config;
use Hush\Storage\Database;
use Hush\Support\SystemClock;
use Hush\Vault\SecretRepository;
use Hush\Vault\VaultException;
use Hush\Vault\VaultService;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$database = $argv[1] ?? '';
$id = $argv[2] ?? '';
$startAt = (float) ($argv[3] ?? '0');

$vault = new VaultService(
    new SecretRepository(Database::connect($database)),
    new Config(dirname(__DIR__, 2), $database),
    new SystemClock(),
);

while (microtime(true) < $startAt) {
    usleep(200);
}

try {
    $opened = $vault->open($id);
    foreach ($opened->package as $piece) {
        // drain the stream like the HTTP emitter does
    }
    echo 'won';
} catch (VaultException) {
    echo 'lost';
}
