<?php

declare(strict_types=1);

namespace Hush\Middleware;

use Hush\Http\Request;
use Hush\Http\Response;

interface Handler
{
    public function handle(Request $request): Response;
}
