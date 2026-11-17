<?php

declare(strict_types=1);

namespace Hush\Api;

use Hush\Http\Request;
use Hush\Http\Response;

final class HealthController
{
    public function health(Request $request): Response
    {
        return Response::json(['status' => 'ok']);
    }
}
