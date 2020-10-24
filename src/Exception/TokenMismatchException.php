<?php

declare(strict_types=1);

namespace Chiron\Csrf\Exception;

use Chiron\Http\Exception\Client\ForbiddenHttpException;

/**
 * Represents an HTTP 403 error caused by a mismatched CSRF token
 */
class TokenMismatchException extends ForbiddenHttpException
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
            $message = 'Access to the specified resource has been forbidden because CSRF verification failed.';
        }

        parent::__construct($message);
    }
}
