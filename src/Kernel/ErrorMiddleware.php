<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;
use Hush\Support\Logger;
use Throwable;

/**
 * Outermost layer: expected errors become their HTTP response, anything else
 * becomes a generic 500 whose details go to the log, never to the client.
 */
final class ErrorMiddleware implements Middleware
{
    public function __construct(
        private readonly ErrorRenderer $renderer,
        private readonly Logger $logger,
    ) {}

    public function process(Request $request, Handler $next): Response
    {
        try {
            return $next->handle($request);
        } catch (HttpException $error) {
            return $this->renderer->render($error, $request);
        } catch (Throwable $error) {
            $this->logger->error(sprintf(
                '%s: %s at %s:%d',
                $error::class,
                $error->getMessage(),
                basename($error->getFile()),
                $error->getLine(),
            ));

            return $this->renderer->render(
                new HttpException(500, 'internal_error', 'Something went wrong on the server.'),
                $request,
            );
        }
    }
}
