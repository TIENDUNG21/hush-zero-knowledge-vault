<?php

declare(strict_types=1);

namespace Hush\Crypto;

use Normalizer;

/**
 * Derives the AES-256-GCM content key.
 *
 *   pw  = PBKDF2-HMAC-SHA256(NFC(password), salt, iterations, 32)   (only with a password)
 *   key = HKDF-SHA256(ikm = fragmentKey || pw, salt, "hush/v1 content key", 32)
 *
 * The fragment key alone is 256 random bits; the password adds a second
 * factor that someone holding only the link cannot guess offline cheaply.
 */
final class KeySchedule
{
    public static function contentKey(string $fragmentKey, Header $header, ?string $password): string
    {
        if (strlen($fragmentKey) !== Format::KEY_LENGTH) {
            throw CryptoException::format('The link key must be 32 bytes');
        }

        $ikm = $fragmentKey;
        if ($header->passwordProtected) {
            if ($password === null || $password === '') {
                throw CryptoException::passwordRequired();
            }
            $iterations = $header->iterations;
            if ($iterations < Format::MIN_ITERATIONS) {
                throw CryptoException::format('PBKDF2 iteration count is too low');
            }
            $ikm .= hash_pbkdf2('sha256', self::normalizePassword($password), $header->salt, $iterations, Format::KEY_LENGTH, true);
        }

        return hash_hkdf('sha256', $ikm, Format::KEY_LENGTH, Format::HKDF_INFO, $header->salt);
    }

    /**
     * NFC so that "é" typed as one code point or as e + combining accent
     * (common with Vietnamese input methods) derives the same key.
     */
    public static function normalizePassword(string $password): string
    {
        if (preg_match('//u', $password) !== 1) {
            throw CryptoException::format('Password must be valid UTF-8');
        }
        if (preg_match('/\A[\x00-\x7f]*\z/', $password) === 1) {
            return $password; // ASCII is already NFC
        }
        if (!class_exists(Normalizer::class)) {
            throw CryptoException::unsupported('Non-ASCII passwords need the PHP intl extension for NFC normalization');
        }
        $normalized = Normalizer::normalize($password, Normalizer::FORM_C);
        if (!is_string($normalized)) {
            throw CryptoException::format('Password could not be normalized');
        }

        return $normalized;
    }
}
