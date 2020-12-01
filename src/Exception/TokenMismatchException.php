<?php

declare(strict_types=1);

namespace Chiron\Csrf\Exception;

use Chiron\Http\Exception\Client\PreconditionFailedHttpException;

/**
 * Represents an HTTP 412 error caused by a mismatched CSRF token
 */
class TokenMismatchException extends PreconditionFailedHttpException
{
    /**
     * Constructor
     *
     * @param string|null $message If no message is given a default message will be used.
     */
    public function __construct(?string $message = null)
    {
        if ($message === null) {
            $message = 'Cannot access the specified resource because CSRF verification failed.';
        }

        parent::__construct($message);
    }
}
