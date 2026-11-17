<?php

declare(strict_types=1);

namespace Hush\Security;

use Hush\Http\Request;

/**
 * Who is the client, for rate limiting only.
 */
final class ClientIp
{
    /**
     * The peer address, or - when the peer is a trusted proxy - the right-most
     * X-Forwarded-For entry that is not itself a trusted proxy.
     *
     * @param list<string> $trustedProxies
     */
    public static function resolve(Request $request, array $trustedProxies): string
    {
        $peer = $request->remoteAddress();
        if (!in_array($peer, $trustedProxies, true)) {
            return $peer;
        }

        $forwarded = array_reverse(array_map('trim', explode(',', $request->header('X-Forwarded-For') ?? '')));
        foreach ($forwarded as $hop) {
            if (filter_var($hop, FILTER_VALIDATE_IP) === false) {
                return $peer; // a malformed chain is not trusted any further
            }
            if (!in_array($hop, $trustedProxies, true)) {
                return $hop;
            }
        }

        return $peer;
    }

    /**
     * IPv4 addresses limit individually; IPv6 clients are grouped by /64,
     * because one host usually controls a whole /64.
     */
    public static function bucketKey(string $ip): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return 'invalid';
        }
        if (strlen($packed) === 4) {
            return 'v4:' . $ip;
        }
        if (str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
            return 'v4:' . inet_ntop(substr($packed, 12));
        }

        return 'v6:' . bin2hex(substr($packed, 0, 8)) . '/64';
    }
}
