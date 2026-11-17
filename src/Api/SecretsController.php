<?php

declare(strict_types=1);

namespace Hush\Api;

use Closure;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Support\Json;
use Hush\Vault\Token;
use Hush\Vault\VaultException;
use Hush\Vault\VaultService;

/**
 * JSON/binary API over {@see VaultService}. Nothing here ever sees a key:
 * request bodies are ciphertext and the public envelope header.
 */
final class SecretsController
{
    public function __construct(private readonly VaultService $vault) {}

    /** POST /api/secrets */
    public function create(Request $request): Response
    {
        $this->requireContentType($request, 'application/json');
        $data = Json::object($request->body());
        $header = Json::base64Url($data, 'header');
        $meta = Json::base64Url($data, 'meta');
        $expiresIn = Json::int($data, 'expiresIn');
        $maxViews = Json::int($data, 'maxViews');

        $created = $this->guard(fn() => $this->vault->create($header, $meta, $expiresIn, $maxViews));

        return Response::json([
            'id' => $created->id,
            'deletionToken' => $created->deletionToken,
            'expiresAt' => $created->expiresAt,
            'uploadDeadline' => $created->uploadDeadline,
            'chunkCount' => $created->chunkCount,
        ], 201)->withHeader('Location', '/api/secrets/' . $created->id);
    }

    /** PUT /api/secrets/{id}/chunks/{index} */
    public function putChunk(Request $request): Response
    {
        $this->requireContentType($request, 'application/octet-stream');
        $token = $this->token($request);
        $id = $request->routeParam('id');
        $index = (int) $request->routeParam('index');

        $this->guard(fn() => $this->vault->putChunk($id, $index, $token, $request->body()));

        return Response::noContent();
    }

    /** POST /api/secrets/{id}/seal */
    public function seal(Request $request): Response
    {
        $token = $this->token($request);
        $id = $request->routeParam('id');
        $this->guard(fn() => $this->vault->seal($id, $token));

        return Response::json(['id' => $id, 'state' => 'sealed']);
    }

    /** GET /api/secrets/{id} (does not consume a view) */
    public function status(Request $request): Response
    {
        $status = $this->guard(fn() => $this->vault->status($request->routeParam('id')));

        return Response::json([
            'id' => $status->id,
            'passwordProtected' => $status->passwordProtected,
            'expiresAt' => $status->expiresAt,
            'viewsLeft' => $status->viewsLeft,
            'chunkCount' => $status->chunkCount,
            'ciphertextBytes' => $status->ciphertextBytes,
        ]);
    }

    /** POST /api/secrets/{id}/open (consumes a view; POST so link previews cannot burn it) */
    public function open(Request $request): Response
    {
        $opened = $this->guard(fn() => $this->vault->open($request->routeParam('id')));

        return Response::bytes($opened->package, 'application/octet-stream', $opened->packageLength)
            ->withHeader('X-Hush-Views-Left', (string) $opened->viewsLeft);
    }

    /** DELETE /api/secrets/{id} */
    public function delete(Request $request): Response
    {
        $token = $this->token($request);
        $id = $request->routeParam('id');
        $this->guard(fn() => $this->vault->delete($id, $token));

        return Response::noContent();
    }

    private function token(Request $request): string
    {
        $token = Token::fromAuthorization($request->header('Authorization'));
        if ($token === null) {
            throw HttpException::unauthorized('Send the deletion token as "Authorization: Bearer <token>".');
        }

        return $token;
    }

    private function requireContentType(Request $request, string $expected): void
    {
        $type = strtolower(trim(explode(';', $request->header('Content-Type') ?? '', 2)[0]));
        if ($type !== $expected) {
            throw HttpException::unsupportedMediaType($expected);
        }
    }

    /**
     * @template T
     *
     * @param Closure(): T $action
     *
     * @return T
     */
    private function guard(Closure $action): mixed
    {
        try {
            return $action();
        } catch (VaultException $e) {
            throw match ($e->kind) {
                'not_found' => HttpException::notFound($e->getMessage()),
                'forbidden' => HttpException::forbidden($e->errorCode, $e->getMessage()),
                'conflict' => HttpException::conflict($e->errorCode, $e->getMessage()),
                'too_large' => new HttpException(413, $e->errorCode, $e->getMessage()),
                default => HttpException::unprocessable($e->errorCode, $e->getMessage()),
            };
        }
    }
}
