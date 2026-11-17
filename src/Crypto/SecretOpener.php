<?php

declare(strict_types=1);

namespace Hush\Crypto;

/**
 * Decrypts and verifies a {@see Package}. Every structural rule is checked
 * after authentication, so a reordered, truncated, extended or re-chunked
 * envelope fails even if each record decrypts on its own.
 */
final class SecretOpener
{
    public static function open(Package $package, string $fragmentKey, ?string $password = null): PlainSecret
    {
        $header = $package->header;
        $key = KeySchedule::contentKey($fragmentKey, $header, $password);

        $meta = Meta::parse(RecordCipher::open($key, Format::aad($package->headerBytes, Format::KIND_META, 0), $package->meta));

        if (count($package->chunks) !== $header->chunkCount) {
            throw CryptoException::integrity(sprintf('Expected %d chunks, got %d', $header->chunkCount, count($package->chunks)));
        }

        $data = '';
        $last = $header->chunkCount - 1;
        foreach ($package->chunks as $index => $record) {
            $plaintext = RecordCipher::open($key, Format::aad($package->headerBytes, Format::KIND_CHUNK, $index), $record);
            $length = strlen($plaintext);
            if (($index < $last && $length !== $header->chunkSize) || ($index === $last && $length > $header->chunkSize)) {
                throw CryptoException::integrity(sprintf('Chunk %d has an unexpected length', $index));
            }
            $data .= $plaintext;
        }

        $padded = Format::paddedLength($meta->size);
        if (strlen($data) !== $padded || Format::chunkCount($padded, $header->chunkSize) !== $header->chunkCount) {
            throw CryptoException::integrity('Payload length does not match the metadata');
        }

        return PlainSecret::fromMeta($meta, substr($data, 0, $meta->size));
    }
}
