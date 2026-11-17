<?php

declare(strict_types=1);

namespace Hush\Web;

use Hush\Config\Config;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;

/**
 * Serves files from resources/assets through the kernel, so scripts and
 * styles get the same security headers as pages under php -S and Apache.
 * Only known extensions inside the asset root are served.
 */
final class AssetController
{
    /** @var array<string, string> */
    public const array TYPES = [
        'js' => 'text/javascript; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'svg' => 'image/svg+xml',
        'png' => 'image/png',
        'woff2' => 'font/woff2',
    ];

    private readonly string $root;

    public function __construct(Config $config)
    {
        $this->root = $config->projectRoot . '/resources/assets';
    }

    public function serve(Request $request): Response
    {
        $path = $request->routeParam('path');
        $file = $this->resolve($path);
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));

        $contents = file_get_contents($file);
        if ($contents === false) {
            throw HttpException::notFound();
        }
        $etag = '"' . substr(hash('sha256', $contents), 0, 32) . '"';

        // Revalidate on every load so a fixed script reaches users at once.
        if ($request->header('If-None-Match') === $etag) {
            return (new Response(304))->withHeader('ETag', $etag)->withHeader('Cache-Control', 'no-cache');
        }

        return Response::bytes($contents, self::TYPES[$extension] ?? 'application/octet-stream')
            ->withHeader('ETag', $etag)
            ->withHeader('Cache-Control', 'no-cache');
    }

    private function resolve(string $path): string
    {
        $segments = explode('/', $path);
        foreach ($segments as $segment) {
            if ($segment === '' || $segment[0] === '.') {
                throw HttpException::notFound();
            }
        }
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!isset(self::TYPES[$extension])) {
            throw HttpException::notFound();
        }

        $root = realpath($this->root);
        $file = realpath($this->root . '/' . $path);
        if ($root === false || $file === false || !is_file($file) || !str_starts_with($file, $root . DIRECTORY_SEPARATOR)) {
            throw HttpException::notFound();
        }

        return $file;
    }
}
