<?php

declare(strict_types=1);

use Chiron\Core\Exception\ScopeException;
use Psr\Http\Message\ServerRequestInterface;
use Chiron\Csrf\Middleware\CsrfTokenMiddleware;

if (! function_exists('csrf_token')) {
    /**
     * Get 'csrf token' request attribute value.
     *
     * @throws ScopeException
     *
     * @return string
     */
    function csrf_token(): string
    {
        $request = container(ServerRequestInterface::class);
        $token = $request->getAttribute(CsrfTokenMiddleware::ATTRIBUTE);

        if ($token === null) {
            throw new ScopeException('Unable to resolve Csrf Token, invalid request scope.');
        }

        return $token;
    }
}
