<?php

declare(strict_types=1);

namespace Hush\Support;

use Hush\Http\HttpException;
use JsonException;

/**
 * Strict decoding of JSON request bodies into typed values.
 */
final class Json
{
    /**
     * @return array<string, mixed>
     */
    public static function object(string $body): array
    {
        try {
            $data = json_decode($body, true, 8, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (JsonException) {
            throw HttpException::badRequest('invalid_json', 'The request body is not valid JSON.');
        }
        if (!is_array($data) || array_is_list($data) && $data !== []) {
            throw HttpException::badRequest('invalid_json', 'The request body must be a JSON object.');
        }
        $out = [];
        foreach ($data as $key => $value) {
            $out[(string) $key] = $value;
        }

        return $out;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!is_string($value)) {
            throw HttpException::unprocessable('invalid_field', sprintf('"%s" must be a string.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function int(array $data, string $key): int
    {
        $value = $data[$key] ?? null;
        if (!is_int($value)) {
            throw HttpException::unprocessable('invalid_field', sprintf('"%s" must be an integer.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function base64Url(array $data, string $key): string
    {
        try {
            return Base64Url::decode(self::string($data, $key));
        } catch (\InvalidArgumentException) {
            throw HttpException::unprocessable('invalid_field', sprintf('"%s" must be base64url without padding.', $key));
        }
    }
}
