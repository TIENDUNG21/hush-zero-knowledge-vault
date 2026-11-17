<?php

declare(strict_types=1);

namespace Hush\Crypto;

/**
 * Encrypts a {@see PlainSecret} into the HUSH v1 envelope.
 */
final class SecretSealer
{
    public static function seal(PlainSecret $secret, SealOptions $options = new SealOptions()): SealedSecret
    {
        $fragmentKey = $options->fragmentKey ?? random_bytes(Format::KEY_LENGTH);
        $salt = $options->salt ?? random_bytes(Format::SALT_LENGTH);
        $nonces = $options->nonces ?? static fn(): string => random_bytes(Format::NONCE_LENGTH);

        $paddedLength = Format::paddedLength(strlen($secret->data));
        $header = new Header(
            $options->hasPassword(),
            $options->hasPassword() ? $options->iterations : 0,
            $salt,
            $options->chunkSize,
            Format::chunkCount($paddedLength, $options->chunkSize),
        );
        $headerBytes = $header->encode();
        $key = KeySchedule::contentKey($fragmentKey, $header, $options->password);

        $metaRecord = RecordCipher::seal(
            $key,
            Format::aad($headerBytes, Format::KIND_META, 0),
            $secret->meta()->encode(),
            $nonces(),
        );

        return new SealedSecret($fragmentKey, $header, $headerBytes, $metaRecord, $key, $secret->data, $paddedLength, $nonces);
    }
}
