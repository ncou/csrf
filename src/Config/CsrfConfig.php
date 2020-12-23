<?php

declare(strict_types=1);

namespace Chiron\Csrf\Config;

use Chiron\Config\AbstractInjectableConfig;
use Nette\Schema\Expect;
use Nette\Schema\Schema;

// EXEMPLE DJANGO Documentation : https://docs.djangoproject.com/en/3.1/ref/settings/#std:setting-CSRF_HEADER_NAME

//https://github.com/codeigniter4/CodeIgniter4/blob/2d9d652c1eada3aad7c17705df1dd99aa0c837b3/app/Config/App.php#L308
//https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
//https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute

final class CsrfConfig extends AbstractInjectableConfig
{
    protected const CONFIG_SECTION_NAME = 'csrf';

    protected function getConfigSchema(): Schema
    {
        return Expect::structure([
            'cookie_name' => Expect::string()->default('csrf-token'),
            'cookie_age'  => Expect::int()->min(0)->default(31449600),
        ]);
    }

    /**
     * @return string
     */
    // TODO : utiliser une regex pour valider le nom du cookie => https://github.com/yiisoft/cookies/blob/master/src/Cookie.php#L35     /   https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Set-Cookie
    public function getCookieName(): string
    {
        return $this->get('cookie_name');
    }

    /**
     * @return int
     */
    public function getCookieAge(): int
    {
        return $this->get('cookie_age');
    }
}
