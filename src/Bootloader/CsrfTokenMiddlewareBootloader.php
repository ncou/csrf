<?php

namespace Chiron\Csrf\Bootloader;

use Chiron\Bootload\AbstractBootloader;
use Chiron\Http\MiddlewareQueue;
use Chiron\Csrf\Middleware\CsrfTokenMiddleware;

final class CsrfTokenMiddlewareBootloader extends AbstractBootloader
{
    public function boot(MiddlewareQueue $middlewares): void
    {
        // add the csrf token middleware AFTER the EncryptCookieMiddleware (defined with PRIORITY_MAX - 10).
        $middlewares->addMiddleware(CsrfTokenMiddleware::class, MiddlewareQueue::PRIORITY_HIGH);
    }
}
