<?php

declare(strict_types=1);

namespace Hush\Crypto;

use InvalidArgumentException;

/**
 * A decrypted (or not yet encrypted) secret: UTF-8 text or a file.
 */
final class PlainSecret
{
    private function __construct(
        public readonly string $kind,
        public readonly string $data,
        public readonly ?string $name,
        public readonly ?string $type,
    ) {}

    public static function text(string $text): self
    {
        if (preg_match('//u', $text) !== 1) {
            throw new InvalidArgumentException('Text secrets must be valid UTF-8; send binary data as a file');
        }

        return new self(Meta::KIND_TEXT, $text, null, null);
    }

    public static function file(string $data, string $name, ?string $type = null): self
    {
        $meta = new Meta(Meta::KIND_FILE, $name, $type, strlen($data)); // validates name and type

        return new self(Meta::KIND_FILE, $data, $meta->name, $meta->type);
    }

    public static function fromMeta(Meta $meta, string $data): self
    {
        if ($meta->kind === Meta::KIND_TEXT && preg_match('//u', $data) !== 1) {
            throw CryptoException::integrity('Text payload is not valid UTF-8');
        }

        return new self($meta->kind, $data, $meta->name, $meta->type);
    }

    public function meta(): Meta
    {
        return new Meta($this->kind, $this->name, $this->type, strlen($this->data));
    }
}
