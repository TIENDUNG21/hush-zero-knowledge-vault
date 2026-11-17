<?php

declare(strict_types=1);

namespace Hush\Web;

use Hush\Config\Config;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Vault\VaultService;

/**
 * Serves the three HTML pages. They are identical for every secret (the
 * id and key are read by JavaScript), so rendering one never touches the
 * database and a link-preview bot fetching /s/... learns nothing and
 * consumes nothing.
 */
final class PageController
{
    public function __construct(
        private readonly TemplateRenderer $templates,
        private readonly Config $config,
    ) {}

    public function create(Request $request): Response
    {
        return Response::html($this->templates->page('create', [
            'title' => 'Share a secret',
            'script' => 'create',
            'maxBytes' => $this->config->maxSecretBytes,
            'maxTtl' => $this->config->maxTtlSeconds,
            'maxViews' => VaultService::MAX_VIEWS,
        ]));
    }

    public function view(Request $request): Response
    {
        return Response::html($this->templates->page('view', ['title' => 'Open a secret', 'script' => 'view']));
    }

    public function delete(Request $request): Response
    {
        return Response::html($this->templates->page('delete', ['title' => 'Delete a secret', 'script' => 'delete']));
    }
}
