<?php

declare(strict_types=1);

namespace Hush\Crypto;

/**
 * Constants and small pure functions of the HUSH v1 envelope format.
 * The JavaScript twin is resources/assets/js/core/format.js; both are
 * pinned by tests/fixtures/vector-v1.json.
 */
final class Format
{
    public const string MAGIC = 'HUSH';
    public const int VERSION = 1;
    public const int HEADER_LENGTH = 36;
    public const int FLAG_PASSWORD = 0x01;

    public const int KEY_LENGTH = 32;
    public const int SALT_LENGTH = 16;
    public const int NONCE_LENGTH = 12;
    public const int TAG_LENGTH = 16;
    public const int RECORD_OVERHEAD = self::NONCE_LENGTH + self::TAG_LENGTH;

    public const int PAD_BLOCK = 256;
    public const int META_MAX_LENGTH = 4096;

    public const int MIN_ITERATIONS = 100_000;
    public const int MAX_ITERATIONS = 5_000_000;
    public const int DEFAULT_ITERATIONS = 600_000;

    public const int MIN_CHUNK_SIZE = 1024;
    public const int MAX_CHUNK_SIZE = 1_048_576;
    public const int DEFAULT_CHUNK_SIZE = 524_288;

    public const int KIND_META = 0;
    public const int KIND_CHUNK = 1;

    public const string HKDF_INFO = 'hush/v1 content key';

    /**
     * Payload length after zero padding: a multiple of 256, at least 256.
     * Hides the exact length of short secrets from the server.
     */
    public static function paddedLength(int $size): int
    {
        return max(self::PAD_BLOCK, intdiv($size + self::PAD_BLOCK - 1, self::PAD_BLOCK) * self::PAD_BLOCK);
    }

    /**
     * Default chunk size for large payloads, otherwise one right-sized chunk,
     * so the header never reserves more than needed on the server.
     */
    public static function chooseChunkSize(int $size): int
    {
        return min(self::DEFAULT_CHUNK_SIZE, max(self::MIN_CHUNK_SIZE, self::paddedLength($size)));
    }

    public static function chunkCount(int $paddedLength, int $chunkSize): int
    {
        return intdiv($paddedLength + $chunkSize - 1, $chunkSize);
    }

    /**
     * Additional authenticated data for record $index of $kind: binds every
     * record to this header (salt, sizes, count) and to its position.
     */
    public static function aad(string $headerBytes, int $kind, int $index): string
    {
        return $headerBytes . chr($kind) . pack('N', $index);
    }
}
