<?php

declare(strict_types=1);

namespace Chiron\Csrf\Exception;

/**
 * Represents an HTTP 412 error caused during trusted Origin verification.
 */
final class UntrustedOriginException extends BadOriginException
{
    public function __construct(string $referer)
    {
        $detail = sprintf('CSRF verification failed because "%s" does not match any trusted origins.', $referer);

        parent::__construct($detail);
    }
}
