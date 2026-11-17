<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;

/**
 * Renders {"error": {"code": ..., "message": ...}} with the exception's headers.
 */
final class JsonErrorRenderer implements ErrorRenderer
{
    public function render(HttpException $error, Request $request): Response
    {
        $response = Response::json(
            ['error' => ['code' => $error->errorCode, 'message' => $error->getMessage()]],
            $error->status,
        );
        foreach ($error->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
