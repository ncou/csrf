<?php

declare(strict_types=1);

use Chiron\Core\Exception\ScopeException;
use Chiron\Csrf\Middleware\CsrfTokenMiddleware;
use Psr\Http\Message\ServerRequestInterface;

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
