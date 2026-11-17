<?php

declare(strict_types=1);

namespace Hush\Web;

use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Kernel\ErrorRenderer;
use Hush\Kernel\JsonErrorRenderer;
use Throwable;

/**
 * JSON errors for the API, a small HTML page for everything a person might
 * open in a browser.
 */
final class PageAwareErrorRenderer implements ErrorRenderer
{
    public function __construct(
        private readonly JsonErrorRenderer $json,
        private readonly TemplateRenderer $templates,
    ) {}

    public function render(HttpException $error, Request $request): Response
    {
        $path = $request->path();
        if (str_starts_with($path, '/api/') || $path === '/healthz' || str_starts_with($path, '/assets/')) {
            return $this->json->render($error, $request);
        }

        try {
            $html = $this->templates->page('error', [
                'title' => $error->status === 404 ? 'Not found' : 'Error',
                'status' => $error->status,
                'message' => $error->status >= 500 ? 'Something went wrong on the server.' : $error->getMessage(),
            ]);
        } catch (Throwable) {
            return $this->json->render($error, $request);
        }

        $response = Response::html($html, $error->status);
        foreach ($error->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
