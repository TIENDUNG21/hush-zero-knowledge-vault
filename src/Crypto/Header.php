<?php

declare(strict_types=1);

namespace Hush\Crypto;

/**
 * The public 36-byte envelope header.
 *
 *   0  4  magic "HUSH"         12 16 salt
 *   4  1  version = 1          28  4 chunk size (u32 BE, multiple of 256)
 *   5  1  flags (bit 0 = pw)   32  4 chunk count (u32 BE)
 *   6  2  reserved = 0
 *   8  4  PBKDF2 iterations (u32 BE, 0 without password)
 *
 * The server parses it to enforce size limits; it reveals nothing secret.
 */
final class Header
{
    public function __construct(
        public readonly bool $passwordProtected,
        public readonly int $iterations,
        public readonly string $salt,
        public readonly int $chunkSize,
        public readonly int $chunkCount,
    ) {
        self::validate($passwordProtected, $iterations, $salt, $chunkSize, $chunkCount);
    }

    public static function parse(string $bytes): self
    {
        if (strlen($bytes) !== Format::HEADER_LENGTH) {
            throw CryptoException::format(sprintf('Header must be %d bytes, got %d', Format::HEADER_LENGTH, strlen($bytes)));
        }
        if (substr($bytes, 0, 4) !== Format::MAGIC) {
            throw CryptoException::format('Not a Hush envelope (bad magic)');
        }
        $version = ord($bytes[4]);
        if ($version !== Format::VERSION) {
            throw CryptoException::format(sprintf('Unsupported envelope version %d', $version));
        }
        $flags = ord($bytes[5]);
        if (($flags & ~Format::FLAG_PASSWORD) !== 0) {
            throw CryptoException::format(sprintf('Unknown header flags 0x%02x', $flags));
        }
        if (substr($bytes, 6, 2) !== "\0\0") {
            throw CryptoException::format('Reserved header bytes must be zero');
        }

        return new self(
            ($flags & Format::FLAG_PASSWORD) !== 0,
            self::u32($bytes, 8),
            substr($bytes, 12, Format::SALT_LENGTH),
            self::u32($bytes, 28),
            self::u32($bytes, 32),
        );
    }

    public function encode(): string
    {
        return Format::MAGIC
            . chr(Format::VERSION)
            . chr($this->passwordProtected ? Format::FLAG_PASSWORD : 0)
            . "\0\0"
            . pack('N', $this->iterations)
            . $this->salt
            . pack('N', $this->chunkSize)
            . pack('N', $this->chunkCount);
    }

    /**
     * Largest plaintext this header can describe (used for server-side limits).
     */
    public function maxPayloadBytes(): int
    {
        return $this->chunkSize * $this->chunkCount;
    }

    private static function validate(bool $password, int $iterations, string $salt, int $chunkSize, int $chunkCount): void
    {
        if ($password && ($iterations < Format::MIN_ITERATIONS || $iterations > Format::MAX_ITERATIONS)) {
            throw CryptoException::format(sprintf(
                'PBKDF2 iterations must be between %d and %d',
                Format::MIN_ITERATIONS,
                Format::MAX_ITERATIONS,
            ));
        }
        if (!$password && $iterations !== 0) {
            throw CryptoException::format('Iterations must be 0 when no password is used');
        }
        if (strlen($salt) !== Format::SALT_LENGTH) {
            throw CryptoException::format('Salt must be 16 bytes');
        }
        if ($chunkSize < Format::MIN_CHUNK_SIZE || $chunkSize > Format::MAX_CHUNK_SIZE || $chunkSize % Format::PAD_BLOCK !== 0) {
            throw CryptoException::format(sprintf(
                'Chunk size must be a multiple of %d between %d and %d bytes',
                Format::PAD_BLOCK,
                Format::MIN_CHUNK_SIZE,
                Format::MAX_CHUNK_SIZE,
            ));
        }
        if ($chunkCount < 1 || $chunkCount > 0xFFFFFFFF) {
            throw CryptoException::format('Chunk count must be at least 1');
        }
    }

    private static function u32(string $bytes, int $offset): int
    {
        $value = unpack('N', $bytes, $offset);
        if ($value === false || !is_int($value[1] ?? null)) {
            throw CryptoException::format('Truncated header');
        }

        return $value[1];
    }
}
