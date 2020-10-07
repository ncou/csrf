<?php

declare(strict_types=1);

namespace Chiron\Csrf\Config;

use Chiron\Config\AbstractInjectableConfig;
use Chiron\Config\Helper\Validator;
use Closure;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Twig\Cache\CacheInterface;

//https://github.com/codeigniter4/CodeIgniter4/blob/2d9d652c1eada3aad7c17705df1dd99aa0c837b3/app/Config/App.php#L308
//https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
//https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute

final class CsrfConfig extends AbstractInjectableConfig
{
    protected const CONFIG_SECTION_NAME = 'csrf';

    protected function getConfigSchema(): Schema
    {
        // TODO : il faudrait pas rajouter un booléen pour savoir si on active ou non la partie protection CSRF ????
        // TODO : renommer le champ 'cookie' en 'cookieName'.
        // TODO : virer "length".
        // TODO : ajouter l'attribut "path" et "domain" dans cette config.
        // TODO : attention il faut aussi ajouter les valeurs pour : "secure" et "samesite"
        // TODO : limiter les valeurs de "samesite" à "Lax" et "Strict". avec la valeur par défaut à Lax !!!! Eventuellement 'None' mais ce n'est pas recommandé
        // TODO : ajouter un controle pour que le lifetime soit supérieur ou égal à 0 (et dans ce cas le cookie est valable durant la durée de la session).
        return Expect::structure([
            'cookie'   => Expect::string()->default('csrf-token'),
            'length'   => Expect::int()->default(16),
            'lifetime' => Expect::int()->default(86400),
        ]);

/*
        // enable/disable CSRF protection for this form
        'csrf_protection' => true,
        // the name of the hidden HTML field that stores the token
        'csrf_field_name' => '_token',
*/
    }

    /**
     * @return int
     */
    public function getTokenLength(): int
    {
        return $this->get('length');
    }

    /**
     * @return string
     */
    public function getCookie(): string
    {
        return $this->get('cookie');
    }


    /**
     * @return int|null
     */
    public function getCookieLifetime(): int
    {
        return $this->get('lifetime');
    }

    /**
     * @return bool
     */
    // TODO : code temporaire
    public function isCookieSecure(): bool
    {
        return false;
    }

    /**
     * @return string|null
     */
    // TODO : code temporaire
    public function getSameSite(): ?string
    {
        return null;
    }
}
