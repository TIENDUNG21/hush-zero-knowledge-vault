<?php

declare(strict_types=1);

namespace Hush\Tests\Integration;

use Hush\Tests\Support\VaultFixture;

/**
 * Pages and assets as a browser fetches them.
 */
final class WebIntegrationTest extends IntegrationTestCase
{
    protected static function port(): int
    {
        return 5143;
    }

    public function testCreatePageLoadsOnlySameOriginModuleScripts(): void
    {
        $page = $this->request('GET', '/');

        self::assertSame(200, $page->status);
        self::assertSame('text/html; charset=utf-8', $page->headers->get('Content-Type'));
        self::assertStringContainsString('<script type="module" src="/assets/js/pages/create.js"></script>', $page->body);
        self::assertStringContainsString('data-max-bytes="33554432"', $page->body);
        self::assertSame(0, preg_match('/<script(?![^>]*\ssrc=)/', $page->body), 'no inline scripts');
        self::assertSame(0, preg_match('/\sstyle=|\son[a-z]+=/i', $page->body), 'no inline styles or handlers');
        self::assertSame(0, preg_match('/<(?:input|textarea|select)[^>]*\sname=/', $page->body), 'form fields have no names, so nothing could be submitted');
    }

    public function testViewPageIsStaticAndDoesNotConsumeAView(): void
    {
        [$id] = $this->storeSecret(VaultFixture::sealText(), maxViews: 1);

        $first = $this->request('GET', '/s/' . $id);
        $second = $this->request('GET', '/s/' . str_repeat('Z', 22));

        self::assertSame(200, $first->status);
        self::assertSame($first->body, $second->body, 'the page is identical for every id');
        self::assertStringNotContainsString($id, $first->body);
        self::assertSame(1, $this->request('GET', '/api/secrets/' . $id)->json()['viewsLeft']);
    }

    public function testAssetsHaveTypesAndRevalidation(): void
    {
        $js = $this->request('GET', '/assets/js/core/crypto.js');
        self::assertSame(200, $js->status);
        self::assertSame('text/javascript; charset=utf-8', $js->headers->get('Content-Type'));
        self::assertSame('no-cache', $js->headers->get('Cache-Control'));
        self::assertSame('nosniff', $js->headers->get('X-Content-Type-Options'));
        $etag = $js->headers->get('ETag');
        self::assertNotNull($etag);

        $cached = $this->request('GET', '/assets/js/core/crypto.js', ['If-None-Match' => $etag]);
        self::assertSame(304, $cached->status);
        self::assertSame('', $cached->body);

        self::assertSame('text/css; charset=utf-8', $this->request('GET', '/assets/css/hush.css')->headers->get('Content-Type'));
        self::assertSame('image/svg+xml', $this->request('GET', '/assets/img/logo.svg')->headers->get('Content-Type'));
    }

    public function testAssetTraversalAndUnknownTypesAreNotFound(): void
    {
        foreach ([
            '/assets/../composer.json',
            '/assets/js/../../templates/layout.php',
            '/assets/js/%2e%2e/%2e%2e/templates/layout.php',
            '/assets/.htaccess',
            '/assets/js/core/missing.js',
            '/assets/css/hush.css.bak',
            '/assets//js/core/bytes.js',
        ] as $path) {
            self::assertSame(404, $this->request('GET', $path)->status, $path);
        }
    }

    public function testUnknownPagesGetAnHtmlErrorPage(): void
    {
        $missing = $this->request('GET', '/nothing-here');

        self::assertSame(404, $missing->status);
        self::assertStringStartsWith('text/html', $missing->headers->get('Content-Type') ?? '');
        self::assertStringContainsString('<p class="status-code">404</p>', $missing->body);
        self::assertStringContainsString("default-src 'none'", $missing->headers->get('Content-Security-Policy') ?? '');
    }

    public function testDeletePage(): void
    {
        $page = $this->request('GET', '/d/' . str_repeat('A', 22));

        self::assertSame(200, $page->status);
        self::assertStringContainsString('/assets/js/pages/delete.js', $page->body);
    }
}
