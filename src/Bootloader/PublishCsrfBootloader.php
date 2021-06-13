<?php

declare(strict_types=1);

namespace Chiron\Csrf\Bootloader;

use Chiron\Core\Container\Bootloader\AbstractBootloader;
use Chiron\Core\Directories;
use Chiron\Publisher\Publisher;

final class PublishCsrfBootloader extends AbstractBootloader
{
    public function boot(Publisher $publisher, Directories $directories): void
    {
        // copy the configuration file template from the package "config" folder to the user "config" folder.
        $publisher->add(__DIR__ . '/../../config/csrf.php.dist', $directories->get('@config/csrf.php'));
    }
}
