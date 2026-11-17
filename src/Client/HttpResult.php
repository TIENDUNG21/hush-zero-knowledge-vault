<?php

declare(strict_types=1);

namespace Hush\Client;

use Hush\Http\HeaderBag;

final class HttpResult
{
    public function __construct(
        public readonly int $status,
        public readonly HeaderBag $headers,
        public readonly string $body,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function json(): array
    {
        $data = json_decode($this->body, true, 16);
        if (!is_array($data)) {
            return [];
        }
        $out = [];
        foreach ($data as $key => $value) {
            $out[(string) $key] = $value;
        }

        return $out;
    }
}
