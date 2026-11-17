<?php

declare(strict_types=1);

namespace Hush\Client;

interface HttpTransport
{
    /**
     * @param array<string, string> $headers
     *
     * @throws TransportException when no HTTP response was received
     */
    public function send(string $method, string $url, array $headers = [], string $body = ''): HttpResult;
}
