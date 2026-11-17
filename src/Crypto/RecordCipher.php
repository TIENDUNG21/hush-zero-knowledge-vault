<?php

declare(strict_types=1);

namespace Hush\Crypto;

/**
 * AES-256-GCM over one record: nonce (12) || ciphertext || tag (16).
 */
final class RecordCipher
{
    private const string CIPHER = 'aes-256-gcm';

    public static function seal(string $key, string $aad, string $plaintext, string $nonce): string
    {
        if (strlen($nonce) !== Format::NONCE_LENGTH) {
            throw CryptoException::format('Nonce must be 12 bytes');
        }
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, Format::TAG_LENGTH);
        if ($ciphertext === false || strlen($tag) !== Format::TAG_LENGTH) {
            throw CryptoException::unsupported('OpenSSL could not encrypt with AES-256-GCM');
        }

        return $nonce . $ciphertext . $tag;
    }

    public static function open(string $key, string $aad, string $record): string
    {
        if (strlen($record) <= Format::RECORD_OVERHEAD) {
            throw CryptoException::format('Record is too short');
        }
        $nonce = substr($record, 0, Format::NONCE_LENGTH);
        $tag = substr($record, -Format::TAG_LENGTH);
        $ciphertext = substr($record, Format::NONCE_LENGTH, -Format::TAG_LENGTH);

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($plaintext === false) {
            throw CryptoException::authentication();
        }

        return $plaintext;
    }
}
