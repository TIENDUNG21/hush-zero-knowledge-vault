<?php

declare(strict_types=1);

namespace Hush\Client;

use Hush\Http\HeaderBag;
use InvalidArgumentException;

/**
 * HTTP client on PHP's stream wrapper: no curl, no Composer packages.
 * Redirects are not followed, so a secret is never re-sent to another host.
 */
final class StreamTransport implements HttpTransport
{
    public function __construct(private readonly float $timeoutSeconds = 30.0) {}

    public function send(string $method, string $url, array $headers = [], string $body = ''): HttpResult
    {
        if (preg_match('#\Ahttps?://#i', $url) !== 1) {
            throw new InvalidArgumentException('Only http:// and https:// URLs are supported');
        }

        $lines = ['Connection: close', 'User-Agent: hush-cli/1.0'];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        if ($body !== '' || in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $lines[] = 'Content-Length: ' . strlen($body);
        }

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $lines),
                'content' => $body,
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 1,
                'protocol_version' => 1.1,
                'timeout' => $this->timeoutSeconds,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $stream = @fopen($url, 'rb', false, $context);
        if ($stream === false) {
            $error = error_get_last();
            throw new TransportException(sprintf(
                'Could not reach %s%s',
                parse_url($url, PHP_URL_HOST) ?? $url,
                $error !== null ? ': ' . $error['message'] : '',
            ));
        }
        $wrapperData = stream_get_meta_data($stream)['wrapper_data'] ?? [];
        $responseBody = stream_get_contents($stream);
        fclose($stream);

        $rawHeaders = [];
        foreach (is_array($wrapperData) ? $wrapperData : [] as $line) {
            if (is_string($line)) {
                $rawHeaders[] = $line;
            }
        }
        if ($responseBody === false || $rawHeaders === []) {
            throw new TransportException('Incomplete HTTP response');
        }

        return new HttpResult(self::status($rawHeaders), self::headers($rawHeaders), $responseBody);
    }

    /**
     * @param list<string> $raw
     */
    private static function status(array $raw): int
    {
        // With redirects disabled the last status line is the response's own.
        $status = 0;
        foreach ($raw as $line) {
            if (preg_match('#\AHTTP/\d(?:\.\d)?\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return $status;
    }

    /**
     * @param list<string> $raw
     */
    private static function headers(array $raw): HeaderBag
    {
        $bag = new HeaderBag();
        foreach ($raw as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }
            try {
                $bag = $bag->withAdded(trim($parts[0]), trim($parts[1]));
            } catch (InvalidArgumentException) {
                // ignore malformed response headers
            }
        }

        return $bag;
    }
}
