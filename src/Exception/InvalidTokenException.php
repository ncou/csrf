<?php

declare(strict_types=1);

namespace Chiron\Csrf\Exception;

use Chiron\Http\Exception\Client\PreconditionFailedHttpException;

/**
 * Represents an HTTP 412 error caused by an invalid CSRF token
 */
class InvalidTokenException extends PreconditionFailedHttpException
{
    /**
     * Constructor
     *
     * @param string|null $message If no message is given a default message will be used.
     * @param int|null $code Status code, defaults to 403
     * @param \Throwable|null $previous The previous exception.
     */
    // TODO : il va falloirt modifier le constructeur des HttpException pour gérer le $previous de maniére plus générique/naturelle !!!!
    //public function __construct(?string $message = null, ?int $code = null, ?Throwable $previous = null)
    public function __construct(?string $message = null)
    {
        if ($message === null) {
            $message = 'Request to the specified resource has been aborted because CSRF token is invalid.';
        }

        parent::__construct($message);
    }
}
