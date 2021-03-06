<?php

declare(strict_types=1);

namespace Chiron\Csrf\Exception;

use Chiron\Http\Exception\Client\PreconditionFailedHttpException;

/**
 * Represents an HTTP 400 error caused by a bad Origin value.
 */
class BadOriginException extends PreconditionFailedHttpException
{
}
