<?php

declare(strict_types=1);

namespace Hush\Crypto;

use Closure;
use Generator;
use InvalidArgumentException;

/**
 * Output of {@see SecretSealer}: the link key, the public header, the
 * encrypted metadata record, and chunk records encrypted on demand so a
 * large file never exists twice in memory.
 */
final class SealedSecret
{
    /**
     * @param Closure(): string $nonces
     */
    public function __construct(
        public readonly string $fragmentKey,
        public readonly Header $header,
        public readonly string $headerBytes,
        public readonly string $metaRecord,
        private readonly string $contentKey,
        private readonly string $data,
        private readonly int $paddedLength,
        private readonly Closure $nonces,
    ) {}

    public function chunkRecord(int $index): string
    {
        if ($index < 0 || $index >= $this->header->chunkCount) {
            throw new InvalidArgumentException(sprintf('Chunk %d does not exist', $index));
        }
        $size = $this->header->chunkSize;
        $offset = $index * $size;
        $length = min($size, $this->paddedLength - $offset);
        $plaintext = str_pad(substr($this->data, $offset, $length), $length, "\0");

        return RecordCipher::seal(
            $this->contentKey,
            Format::aad($this->headerBytes, Format::KIND_CHUNK, $index),
            $plaintext,
            ($this->nonces)(),
        );
    }

    /**
     * @return Generator<int, string>
     */
    public function chunkRecords(): Generator
    {
        for ($i = 0; $i < $this->header->chunkCount; $i++) {
            yield $i => $this->chunkRecord($i);
        }
    }

    public function toPackage(): Package
    {
        return new Package($this->headerBytes, $this->metaRecord, iterator_to_array($this->chunkRecords(), false));
    }
}
