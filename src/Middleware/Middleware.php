<?php

declare(strict_types=1);

namespace Hush\Middleware;

use Hush\Http\Request;
use Hush\Http\Response;

/**
 * A layer of the onion: may inspect or replace the request, call $next
 * (or not, to short-circuit), and inspect or replace the response.
 */
interface Middleware
{
    public function process(Request $request, Handler $next): Response;
}
