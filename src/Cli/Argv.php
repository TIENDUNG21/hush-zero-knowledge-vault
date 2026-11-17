<?php

declare(strict_types=1);

namespace Hush\Cli;

/**
 * GNU-style argument parsing: "--name value", "--name=value", boolean
 * flags and "--" to end options. Unknown options are errors, not ignored.
 */
final class Argv
{
    /**
     * @param list<string> $positionals
     * @param array<string, string|true> $options
     */
    private function __construct(
        public readonly array $positionals,
        public readonly array $options,
    ) {}

    /**
     * @param list<string> $args
     * @param array<string, bool> $spec option name => takes a value
     */
    public static function parse(array $args, array $spec): self
    {
        $positionals = [];
        $options = [];
        $count = count($args);
        for ($i = 0; $i < $count; $i++) {
            $arg = $args[$i];
            if ($arg === '--') {
                array_push($positionals, ...array_slice($args, $i + 1));
                break;
            }
            if (!str_starts_with($arg, '--') || $arg === '-') {
                $positionals[] = $arg;
                continue;
            }
            $equals = strpos($arg, '=');
            $name = $equals === false ? substr($arg, 2) : substr($arg, 2, $equals - 2);
            $inline = $equals === false ? null : substr($arg, $equals + 1);
            if (!array_key_exists($name, $spec)) {
                throw new UsageException(sprintf('Unknown option --%s', $name));
            }
            if (!$spec[$name]) {
                if ($inline !== null) {
                    throw new UsageException(sprintf('Option --%s does not take a value', $name));
                }
                $options[$name] = true;
                continue;
            }
            if ($inline === null) {
                if ($i + 1 >= $count) {
                    throw new UsageException(sprintf('Option --%s needs a value', $name));
                }
                $inline = $args[++$i];
            }
            $options[$name] = $inline;
        }

        return new self($positionals, $options);
    }

    public function string(string $name): ?string
    {
        $value = $this->options[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    public function flag(string $name): bool
    {
        return ($this->options[$name] ?? null) === true;
    }
}
