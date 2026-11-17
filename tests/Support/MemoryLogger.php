<?php

declare(strict_types=1);

namespace Hush\Tests\Support;

use Hush\Support\Logger;

final class MemoryLogger implements Logger
{
    /** @var list<string> */
    public array $errors = [];

    public function error(string $message): void
    {
        $this->errors[] = $message;
    }
}
