<?php

declare(strict_types=1);

namespace Hush\Crypto;

use JsonException;

/**
 * Encrypted metadata record: what the payload is and how long it really is.
 * Serialized as JSON with a fixed key order, right-padded with spaces to a
 * multiple of 256 bytes so the file name length does not leak.
 */
final class Meta
{
    public const string KIND_TEXT = 'text';
    public const string KIND_FILE = 'file';

    public function __construct(
        public readonly string $kind,
        public readonly ?string $name,
        public readonly ?string $type,
        public readonly int $size,
    ) {
        if ($kind !== self::KIND_TEXT && $kind !== self::KIND_FILE) {
            throw CryptoException::format(sprintf('Unknown payload kind "%s"', $kind));
        }
        if ($kind === self::KIND_TEXT && ($name !== null || $type !== null)) {
            throw CryptoException::format('Text payloads carry no file name or type');
        }
        if ($name !== null && preg_match('/\A[^\x00-\x1f\x7f]{1,255}\z/u', $name) !== 1) {
            throw CryptoException::format('File name must be 1-255 printable characters');
        }
        if ($type !== null && !self::isMediaType($type)) {
            throw CryptoException::format('Invalid media type');
        }
        if ($size < 0) {
            throw CryptoException::format('Size must not be negative');
        }
    }

    public static function isMediaType(string $type): bool
    {
        return preg_match('#\A[A-Za-z0-9!\#$&^_.+-]{1,63}/[A-Za-z0-9!\#$&^_.+-]{1,63}\z#', $type) === 1;
    }

    public function encode(): string
    {
        $json = json_encode(
            ['kind' => $this->kind, 'name' => $this->name, 'type' => $this->type, 'size' => $this->size],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );
        $padded = str_pad($json, intdiv(strlen($json) + Format::PAD_BLOCK - 1, Format::PAD_BLOCK) * Format::PAD_BLOCK, ' ');
        if (strlen($padded) > Format::META_MAX_LENGTH) {
            throw CryptoException::format('Metadata is too large');
        }

        return $padded;
    }

    public static function parse(string $bytes): self
    {
        if (strlen($bytes) === 0 || strlen($bytes) % Format::PAD_BLOCK !== 0 || strlen($bytes) > Format::META_MAX_LENGTH) {
            throw CryptoException::integrity('Metadata has an invalid padded length');
        }
        try {
            $data = json_decode($bytes, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CryptoException::integrity('Metadata is not valid JSON');
        }
        if (!is_array($data) || array_keys($data) !== ['kind', 'name', 'type', 'size']) {
            throw CryptoException::integrity('Metadata must have exactly kind, name, type and size');
        }
        $kind = $data['kind'];
        $name = $data['name'];
        $type = $data['type'];
        $size = $data['size'];
        if (!is_string($kind) || !(is_string($name) || $name === null) || !(is_string($type) || $type === null) || !is_int($size)) {
            throw CryptoException::integrity('Metadata fields have the wrong types');
        }

        return new self($kind, $name, $type, $size);
    }
}
