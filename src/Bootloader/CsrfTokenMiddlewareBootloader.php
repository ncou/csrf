<?php

declare(strict_types=1);

namespace Chiron\Csrf\Bootloader;

use Chiron\Core\Container\Bootloader\AbstractBootloader;
use Chiron\Csrf\Middleware\CsrfTokenMiddleware;
use Chiron\Http\MiddlewareQueue;

final class CsrfTokenMiddlewareBootloader extends AbstractBootloader
{
    public function boot(MiddlewareQueue $middlewares): void
    {
        // add the csrf token middleware AFTER the EncryptCookieMiddleware (defined with PRIORITY_MAX - 10).
        $middlewares->addMiddleware(CsrfTokenMiddleware::class, MiddlewareQueue::PRIORITY_HIGH);
    }
}
