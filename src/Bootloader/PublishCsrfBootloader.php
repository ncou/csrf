<?php

declare(strict_types=1);

namespace Chiron\Csrf\Bootloader;

use Chiron\Bootload\AbstractBootloader;
use Chiron\Core\Directories;
use Chiron\PublishableCollection;

final class PublishCsrfBootloader extends AbstractBootloader
{
    public function boot(PublishableCollection $publishable, Directories $directories): void
    {
        // copy the configuration file template from the package "config" folder to the user "config" folder.
        $publishable->add(__DIR__ . '/../../config/csrf.php.dist', $directories->get('@config/csrf.php'));
    }
}