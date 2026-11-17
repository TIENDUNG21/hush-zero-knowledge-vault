<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;

/**
 * Turns an {@see HttpException} into a response for the given request.
 */
interface ErrorRenderer
{
    public function render(HttpException $error, Request $request): Response;
}
