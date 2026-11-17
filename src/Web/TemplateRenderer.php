<?php

declare(strict_types=1);

namespace Hush\Web;

use InvalidArgumentException;
use RuntimeException;

/**
 * Plain PHP templates with escaping by default. A page template is rendered
 * first and then wrapped in layout.php.
 *
 * Templates receive $v (the variables) and $e (HTML escaper). Pages contain
 * no user data: the secret id and key are read by JavaScript from the URL.
 */
final class TemplateRenderer
{
    public function __construct(private readonly string $directory) {}

    /**
     * @param array<string, string|int|bool|null> $vars needs at least "title"
     */
    public function page(string $template, array $vars): string
    {
        $content = $this->render($template, $vars);

        return $this->render('layout', $vars + ['content' => $content, 'script' => null]);
    }

    /**
     * @param array<string, string|int|bool|null> $vars
     */
    public function render(string $template, array $vars): string
    {
        if (preg_match('/\A[a-z][a-z-]*\z/', $template) !== 1) {
            throw new InvalidArgumentException(sprintf('Invalid template name "%s"', $template));
        }
        $file = $this->directory . '/' . $template . '.php';
        if (!is_file($file)) {
            throw new RuntimeException(sprintf('Template %s does not exist', $template));
        }

        $e = static fn(string|int|bool|null $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
        $v = $vars;

        ob_start();
        try {
            (static function () use ($file, $v, $e): void {
                require $file;
            })();
        } catch (\Throwable $error) {
            ob_end_clean();
            throw $error;
        }

        return (string) ob_get_clean();
    }
}
