<?php

declare(strict_types=1);

/*
 * Front controller. Works under the PHP built-in server
 * (php -S 127.0.0.1:5140 public/index.php) and under Apache (FallbackResource).
 */

use Hush\Config\Config;
use Hush\Http\RequestFactory;
use Hush\Http\Response;
use Hush\Http\ResponseEmitter;
use Hush\Kernel\Application;

require dirname(__DIR__) . '/vendor/autoload.php';

$emitter = new ResponseEmitter();

try {
    $config = Config::fromEnvironment(getenv(), dirname(__DIR__));
    $kernel = (new Application($config))->kernel();
} catch (Throwable $bootError) {
    error_log('[hush] boot failed: ' . $bootError->getMessage());
    $emitter->emit(Response::json(['error' => ['code' => 'unavailable', 'message' => 'The service is misconfigured.']], 503));

    return;
}

$request = RequestFactory::fromGlobals(
    $_SERVER,
    static function (int $limit): string {
        $input = fopen('php://input', 'rb');
        if ($input === false) {
            return '';
        }
        $body = stream_get_contents($input, $limit);
        fclose($input);

        return $body === false ? '' : $body;
    },
    function_exists('getallheaders') ? getallheaders() : null,
);

$response = $kernel->handle($request);
$emitter->emit($response, $request->method() === 'HEAD');
