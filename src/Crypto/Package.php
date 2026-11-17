<?php

declare(strict_types=1);

namespace Hush\Crypto;

/**
 * Self-contained serialization of an envelope, used for .hush files and for
 * the body of POST /api/secrets/{id}/open:
 *
 *   header (36) || u32 metaLength || meta record || (u32 length || chunk record)*
 */
final class Package
{
    public readonly Header $header;

    /**
     * @param list<string> $chunks
     */
    public function __construct(
        public readonly string $headerBytes,
        public readonly string $meta,
        public readonly array $chunks,
    ) {
        $this->header = Header::parse($headerBytes);
    }

    public static function prefix(string $headerBytes, string $meta): string
    {
        return $headerBytes . self::frame($meta);
    }

    public static function frame(string $record): string
    {
        return pack('N', strlen($record)) . $record;
    }

    public function pack(): string
    {
        $out = self::prefix($this->headerBytes, $this->meta);
        foreach ($this->chunks as $chunk) {
            $out .= self::frame($chunk);
        }

        return $out;
    }

    public static function unpack(string $bytes): self
    {
        $total = strlen($bytes);
        if ($total < Format::HEADER_LENGTH) {
            throw CryptoException::format('Package is truncated before the end of the header');
        }
        $headerBytes = substr($bytes, 0, Format::HEADER_LENGTH);
        $header = Header::parse($headerBytes);

        $offset = Format::HEADER_LENGTH;
        $meta = self::readFrame($bytes, $offset, Format::META_MAX_LENGTH + Format::RECORD_OVERHEAD);

        $chunks = [];
        while ($offset < $total) {
            if (count($chunks) >= $header->chunkCount) {
                throw CryptoException::format('Package has more chunks than its header declares');
            }
            $chunks[] = self::readFrame($bytes, $offset, $header->chunkSize + Format::RECORD_OVERHEAD);
        }

        return new self($headerBytes, $meta, $chunks);
    }

    private static function readFrame(string $bytes, int &$offset, int $maxLength): string
    {
        if ($offset + 4 > strlen($bytes)) {
            throw CryptoException::format('Package is truncated inside a length prefix');
        }
        $length = unpack('N', $bytes, $offset);
        if ($length === false || !is_int($length[1] ?? null)) {
            throw CryptoException::format('Package is truncated inside a length prefix');
        }
        $length = $length[1];
        if ($length <= Format::RECORD_OVERHEAD || $length > $maxLength) {
            throw CryptoException::format(sprintf('Record length %d is out of range', $length));
        }
        if ($offset + 4 + $length > strlen($bytes)) {
            throw CryptoException::format('Package is truncated inside a record');
        }
        $record = substr($bytes, $offset + 4, $length);
        $offset += 4 + $length;

        return $record;
    }
}
