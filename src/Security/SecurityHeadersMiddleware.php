<?php

declare(strict_types=1);

namespace Hush\Security;

use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;

/**
 * Outermost layer: every response, including errors, gets the same strict
 * browser policy.
 *
 * The CSP allows scripts and styles only from this origin (no inline code,
 * no eval), forbids every form submission (so a broken script can never
 * post a plaintext secret), and enforces Trusted Types so DOM XSS sinks
 * such as innerHTML throw.
 */
final class SecurityHeadersMiddleware implements Middleware
{
    public const string CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'self'; style-src 'self'; "
        . "img-src 'self' blob: data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; "
        . "form-action 'none'; base-uri 'none'; frame-ancestors 'none'; "
        . "require-trusted-types-for 'script'; trusted-types 'none'";

    /** @var array<string, string> */
    public const array HEADERS = [
        'Content-Security-Policy' => self::CONTENT_SECURITY_POLICY,
        'Strict-Transport-Security' => 'max-age=63072000; includeSubDomains',
        'Referrer-Policy' => 'no-referrer',
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'Cross-Origin-Resource-Policy' => 'same-origin',
        'Cross-Origin-Embedder-Policy' => 'require-corp',
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-Robots-Tag' => 'noindex, nofollow',
    ];

    public function process(Request $request, Handler $next): Response
    {
        $response = $next->handle($request);
        foreach (self::HEADERS as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        if ($response->header('Cache-Control') === null) {
            $response = $response->withHeader('Cache-Control', 'no-store');
        }

        return $response;
    }
}
