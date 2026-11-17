<?php

declare(strict_types=1);

namespace Hush\Vault;

use Generator;
use Hush\Config\Config;
use Hush\Crypto\CryptoException;
use Hush\Crypto\Format;
use Hush\Crypto\Header;
use Hush\Crypto\Package;
use Hush\Support\Clock;

/**
 * The vault's rules. It only ever handles ciphertext and the public header;
 * it validates sizes and shapes, never content.
 *
 * Lifecycle: create (uploading) -> putChunk* -> seal (sealed) -> open* ->
 * burned on the last view -> purged. Expired, abandoned and burned rows are
 * removed by collectGarbage().
 */
final class VaultService
{
    public const int MIN_TTL = 60;
    public const int MAX_VIEWS = 100;

    public function __construct(
        private readonly SecretRepository $secrets,
        private readonly Config $config,
        private readonly Clock $clock,
    ) {}

    public function create(string $headerBytes, string $metaRecord, int $expiresIn, int $maxViews): CreatedSecret
    {
        try {
            $header = Header::parse($headerBytes);
        } catch (CryptoException $e) {
            throw VaultException::invalid('invalid_header', $e->getMessage());
        }
        if ($header->maxPayloadBytes() > $this->config->maxSecretBytes) {
            throw VaultException::tooLarge(sprintf('Secrets are limited to %d bytes on this server.', $this->config->maxSecretBytes));
        }
        $metaPlainLength = strlen($metaRecord) - Format::RECORD_OVERHEAD;
        if ($metaPlainLength < Format::PAD_BLOCK || $metaPlainLength > Format::META_MAX_LENGTH || $metaPlainLength % Format::PAD_BLOCK !== 0) {
            throw VaultException::invalid('invalid_meta', 'The metadata record has an impossible length.');
        }
        if ($expiresIn < self::MIN_TTL || $expiresIn > $this->config->maxTtlSeconds) {
            throw VaultException::invalid('invalid_expiry', sprintf('expiresIn must be between %d and %d seconds.', self::MIN_TTL, $this->config->maxTtlSeconds));
        }
        if ($maxViews < 1 || $maxViews > self::MAX_VIEWS) {
            throw VaultException::invalid('invalid_views', sprintf('maxViews must be between 1 and %d.', self::MAX_VIEWS));
        }

        $now = $this->clock->timestamp();
        $token = Token::generate();
        $record = new SecretRecord(
            id: SecretId::generate(),
            header: $headerBytes,
            meta: $metaRecord,
            chunkCount: $header->chunkCount,
            chunkSize: $header->chunkSize,
            ownerTokenHash: Token::hash($token),
            state: SecretRecord::UPLOADING,
            maxViews: $maxViews,
            views: 0,
            expiresAt: $now + $expiresIn,
            uploadDeadline: min($now + $this->config->uploadWindowSeconds, $now + $expiresIn),
            burnedAt: null,
        );
        $this->secrets->insert($record);

        return new CreatedSecret($record->id, $token, $record->expiresAt, $record->uploadDeadline, $record->chunkCount);
    }

    public function putChunk(string $id, int $index, string $token, string $record): void
    {
        $secret = $this->owned($id, $token);
        if ($secret->state !== SecretRecord::UPLOADING) {
            throw VaultException::conflict('already_sealed', 'This secret is sealed; chunks can no longer change.');
        }
        if ($this->clock->timestamp() >= $secret->uploadDeadline) {
            throw VaultException::conflict('upload_window_closed', 'The upload window for this secret has closed.');
        }
        if ($index < 0 || $index >= $secret->chunkCount) {
            throw VaultException::invalid('chunk_index_out_of_range', sprintf('Chunk index must be between 0 and %d.', $secret->chunkCount - 1));
        }

        $plainLength = strlen($record) - Format::RECORD_OVERHEAD;
        $isLast = $index === $secret->chunkCount - 1;
        $valid = $isLast
            ? $plainLength >= Format::PAD_BLOCK && $plainLength <= $secret->chunkSize && $plainLength % Format::PAD_BLOCK === 0
            : $plainLength === $secret->chunkSize;
        if (!$valid) {
            throw VaultException::invalid('invalid_chunk_length', sprintf('Chunk %d has an impossible length for this envelope.', $index));
        }

        $this->secrets->putChunk($id, $index, $record);
    }

    public function seal(string $id, string $token): void
    {
        $secret = $this->owned($id, $token);
        if ($secret->state !== SecretRecord::UPLOADING) {
            throw VaultException::conflict('already_sealed', 'This secret is already sealed.');
        }
        $uploaded = $this->secrets->uploadedChunks($id);
        if ($uploaded !== $secret->chunkCount) {
            throw VaultException::conflict('missing_chunks', sprintf('%d of %d chunks uploaded.', $uploaded, $secret->chunkCount));
        }
        if (!$this->secrets->markSealed($id)) {
            throw VaultException::conflict('already_sealed', 'This secret is already sealed.');
        }
    }

    public function status(string $id): SecretStatus
    {
        $secret = $this->secrets->find($id);
        if ($secret === null || !$secret->isReadableAt($this->clock->timestamp())) {
            throw VaultException::notFound();
        }

        return new SecretStatus(
            $secret->id,
            Header::parse($secret->header)->passwordProtected,
            $secret->expiresAt,
            $secret->maxViews - $secret->views,
            $secret->chunkCount,
            strlen($secret->meta) + $this->secrets->storedBytes($id),
            $secret->header,
            $secret->meta,
        );
    }

    /**
     * Consumes one view and returns the package as a stream. On the last
     * view the rows are deleted as soon as the stream has been sent; if the
     * stream is interrupted, garbage collection removes them after the grace period.
     */
    public function open(string $id): OpenedSecret
    {
        $viewsLeft = $this->secrets->claimView($id, $this->clock->timestamp());
        if ($viewsLeft === null) {
            throw VaultException::notFound();
        }
        $secret = $this->secrets->find($id);
        if ($secret === null) {
            throw VaultException::notFound();
        }

        $length = strlen(Package::prefix($secret->header, $secret->meta))
            + 4 * $secret->chunkCount
            + $this->secrets->storedBytes($id);

        return new OpenedSecret($viewsLeft, $length, $this->stream($secret, $viewsLeft === 0));
    }

    public function delete(string $id, string $token): void
    {
        $this->owned($id, $token);
        $this->secrets->purge($id);
    }

    /**
     * @return array{expired: int, abandoned: int, burned: int}
     */
    public function collectGarbage(): array
    {
        $now = $this->clock->timestamp();

        return $this->secrets->collectGarbage($now, $now - $this->config->burnGraceSeconds);
    }

    /**
     * @return Generator<int, string>
     */
    private function stream(SecretRecord $secret, bool $purgeAfter): Generator
    {
        try {
            yield Package::prefix($secret->header, $secret->meta);
            foreach ($this->secrets->chunks($secret->id, $secret->chunkCount) as $record) {
                yield Package::frame($record);
            }
        } finally {
            if ($purgeAfter) {
                $this->secrets->purge($secret->id);
            }
        }
    }

    private function owned(string $id, string $token): SecretRecord
    {
        $secret = $this->secrets->find($id);
        if ($secret === null || $secret->expiresAt <= $this->clock->timestamp() || $secret->state === SecretRecord::BURNED) {
            throw VaultException::notFound();
        }
        if (!Token::matches($token, $secret->ownerTokenHash)) {
            throw VaultException::forbidden();
        }

        return $secret;
    }
}
