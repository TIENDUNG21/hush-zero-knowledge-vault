<?php

declare(strict_types=1);

namespace Hush\Http;

/**
 * Writes a {@see Response} to the SAPI. The only class that calls header().
 */
final class ResponseEmitter
{
    public function emit(Response $response, bool $omitBody = false): void
    {
        if (!headers_sent()) {
            http_response_code($response->status());
            header_remove('X-Powered-By');
            foreach ($response->headers()->all() as $name => $values) {
                foreach ($values as $value) {
                    header($name . ': ' . $value, false);
                }
            }
        }

        if ($omitBody) {
            return;
        }

        foreach ($response->body() as $piece) {
            echo $piece;
            if (ob_get_level() > 0) {
                ob_flush();
            }
            flush();
        }
    }
}
