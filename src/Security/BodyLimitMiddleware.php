<?php

declare(strict_types=1);

namespace Hush\Security;

use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Kernel\RoutingMiddleware;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;

/**
 * Reads the request body with the route's "maxBody" limit (default 0).
 *
 * The declared Content-Length is checked first so oversized uploads are
 * refused before any byte is read; the actual read is bounded too, so a
 * client that lies about its length cannot push more than the limit.
 */
final class BodyLimitMiddleware implements Middleware
{
    public function process(Request $request, Handler $next): Response
    {
        $limit = RoutingMiddleware::matchOf($request)?->attribute('maxBody');
        $limit = is_int($limit) ? $limit : 0;

        if ($request->header('Transfer-Encoding') !== null) {
            throw HttpException::lengthRequired();
        }

        $declared = $request->header('Content-Length');
        if ($declared !== null && preg_match('/\A\d{1,15}\z/', $declared) !== 1) {
            throw HttpException::badRequest('invalid_content_length', 'Content-Length must be a decimal number.');
        }
        $declared = $declared === null ? null : (int) $declared;

        if ($limit === 0) {
            if ($declared !== null && $declared > 0) {
                throw HttpException::payloadTooLarge(0);
            }

            return $next->handle($request->withBody(''));
        }

        if ($declared === null) {
            throw HttpException::lengthRequired();
        }
        if ($declared > $limit) {
            throw HttpException::payloadTooLarge($limit);
        }

        $body = $request->readBody($limit);
        if (strlen($body) > $limit) {
            throw HttpException::payloadTooLarge($limit);
        }
        if (strlen($body) !== $declared) {
            throw HttpException::badRequest('body_length_mismatch', 'The body length does not match Content-Length.');
        }

        return $next->handle($request->withBody($body));
    }
}
