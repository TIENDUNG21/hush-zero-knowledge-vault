<?php

declare(strict_types=1);

namespace Hush\Routing;

use LogicException;

/**
 * One method + path pattern bound to a controller method.
 *
 * Patterns use "{name}" (one path segment) or "{name:regex}" placeholders,
 * e.g. "/api/secrets/{id:[A-Za-z0-9_-]{22}}/chunks/{index:\d{1,6}}".
 */
final class Route
{
    public readonly string $regex;

    /** @var list<string> */
    public readonly array $parameterNames;

    /**
     * @param array{0: class-string, 1: string} $handler
     * @param array<string, string|int|bool> $attributes per-route policy (rate bucket, body limit, ...)
     */
    public function __construct(
        public readonly string $method,
        public readonly string $pattern,
        public readonly array $handler,
        public readonly array $attributes = [],
    ) {
        if (!str_starts_with($pattern, '/')) {
            throw new LogicException(sprintf('Route pattern "%s" must start with "/"', $pattern));
        }
        [$this->regex, $this->parameterNames] = self::compile($pattern);
    }

    /**
     * @return array<string, string>|null decoded parameters when the path matches
     */
    public function matchPath(string $path): ?array
    {
        $result = preg_match($this->regex, $path, $matches);
        if ($result !== 1) {
            return null; // includes invalid UTF-8, which preg reports as an error
        }
        $params = [];
        foreach ($this->parameterNames as $name) {
            $params[$name] = $matches[$name] ?? '';
        }

        return $params;
    }

    /**
     * @return array{0: string, 1: list<string>}
     */
    private static function compile(string $pattern): array
    {
        $regex = '';
        $names = [];
        $length = strlen($pattern);
        $i = 0;
        while ($i < $length) {
            $char = $pattern[$i];
            if ($char !== '{') {
                $regex .= preg_quote($char, '~');
                $i++;
                continue;
            }
            // Find the matching close brace; regex quantifiers like {22} nest inside.
            $depth = 0;
            $end = $i;
            for (; $end < $length; $end++) {
                if ($pattern[$end] === '{') {
                    $depth++;
                } elseif ($pattern[$end] === '}') {
                    $depth--;
                    if ($depth === 0) {
                        break;
                    }
                }
            }
            if ($depth !== 0) {
                throw new LogicException(sprintf('Unbalanced braces in route pattern "%s"', $pattern));
            }
            $body = substr($pattern, $i + 1, $end - $i - 1);
            $parts = explode(':', $body, 2);
            $name = $parts[0];
            $constraint = $parts[1] ?? '[^/]+';
            if (preg_match('/\A[a-z][A-Za-z0-9]*\z/', $name) !== 1 || in_array($name, $names, true)) {
                throw new LogicException(sprintf('Invalid or duplicate parameter "%s" in "%s"', $name, $pattern));
            }
            $names[] = $name;
            $regex .= '(?P<' . $name . '>' . $constraint . ')';
            $i = $end + 1;
        }

        return ['~\A' . $regex . '\z~u', $names];
    }
}
