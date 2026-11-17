<?php

declare(strict_types=1);

namespace Hush\Security;

use Hush\Config\Config;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;

/**
 * CSRF defence for state-changing requests.
 *
 * Browsers send Origin (and Sec-Fetch-Site) on every cross-origin POST, PUT
 * and DELETE; when present they must name this origin. Requests without
 * either header come from non-browser clients such as bin/hush and are
 * allowed: they cannot carry a victim's ambient credentials, and Hush uses
 * no cookies at all.
 */
final class OriginCheckMiddleware implements Middleware
{
    private const array SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    public function __construct(private readonly Config $config) {}

    public function process(Request $request, Handler $next): Response
    {
        if (in_array($request->method(), self::SAFE_METHODS, true)) {
            return $next->handle($request);
        }

        $fetchSite = $request->header('Sec-Fetch-Site');
        if ($fetchSite !== null && !in_array(strtolower($fetchSite), ['same-origin', 'none'], true)) {
            throw HttpException::forbidden('cross_origin', 'Cross-site requests are not allowed.');
        }

        $origin = $request->header('Origin');
        if ($origin !== null && strtolower($origin) !== strtolower($this->expectedOrigin($request))) {
            throw HttpException::forbidden('cross_origin', 'Cross-origin requests are not allowed.');
        }

        return $next->handle($request);
    }

    private function expectedOrigin(Request $request): string
    {
        if ($this->config->publicOrigin !== null) {
            return $this->config->publicOrigin;
        }

        return ($request->isSecure() ? 'https' : 'http') . '://' . ($request->header('Host') ?? '');
    }
}
