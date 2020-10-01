<?php

declare(strict_types=1);

namespace Chiron\Csrf\Config;

use Chiron\Config\AbstractInjectableConfig;
use Chiron\Config\Helper\Validator;
use Closure;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Twig\Cache\CacheInterface;

final class CsrfConfig extends AbstractInjectableConfig
{
    protected const CONFIG_SECTION_NAME = 'csrf';

    protected function getConfigSchema(): Schema
    {
        // TODO : améliorer le typage des tableaux exemple : Expect::arrayOf(Expect::string(), Expect::type(CacheInterface::class))
        return Expect::structure([
            // general options settings
            'options'       => Expect::structure([
                'debug'            => Expect::bool()->default(setting('debug')),
                'charset'          => Expect::string()->default(setting('charset')), // TODO : il faudrait pas refaire un test sur la validité du Charset ? comme c'est fait pour le settingsConfig ?
                'strict_variables' => Expect::bool()->default(false),
                'autoescape'       => Expect::anyOf(false, Expect::string(), Expect::callable())->default('name'),
                //'cache' => Expect::anyOf(false, Expect::string(), Expect::is(CacheInterface::class))->default(directory('@cache/twig/')),
                'cache'            => Expect::anyOf(false, Expect::string(), Expect::object())->assert(Closure::fromCallable([$this, 'objectIsCacheInterface']), 'instanceof CacheInterface')->default(directory('@cache/twig/')), // TODO : on devrait peut etre ne pas gérer la possibilité de passer un objet Cache*Interface ca simplifierai le code non ????
                'auto_reload'      => Expect::bool()->default(setting('debug')),
                'optimizations'    => Expect::anyOf(-1, 0)->default(-1),
            ]),
            // date settings
            'date'          => Expect::structure([
                'format'          => Expect::string()->default('F j, Y H:i'),
                'interval_format' => Expect::string()->default('%d days'),
                'timezone'        => Expect::string()->nullable()->default(setting('timezone')), // TODO : il faudrait pas refaire un test sur la validité du TimeZone ? comme c'est fait pour le settingsConfig ? Si on ajoute ce controle il ne sera plus nécessaire de lever d'exception dans la méthode "setTimeZone()" de la factory car on sera sur que le format de la timezone est correct !!!!
            ]),
            // number settings
            'number_format' => Expect::structure([
                'decimals'            => Expect::int()->default(0),
                'decimal_point'       => Expect::string()->default('.'),
                'thousands_separator' => Expect::string()->default(','),
            ]),
            // generic parameters
            // TODO : améliorer la vérification des tableaux pour bien vérifier le type d'objet qui sont autorisés dans ces tableaux !!!
            'extensions'    => Expect::array(), // extension could be a string classename or an ExtensionInterface object.
            'functions'     => Expect::array(),
            'filters'       => Expect::array(),
            'globals'       => Expect::arrayOf('string')->assert([Validator::class, 'isArrayAssociative'], 'associative array'),
            'facades'       => Expect::array()->assert(Closure::fromCallable([$this, 'isValidFacadeArray']), 'facades array structure'),
            'lexer'         => Expect::array(),
        ]);
    }

    public function getOptions(): array
    {
        return $this->get('options');
    }

    public function getFacades(): array
    {
        return $this->get('facades');
    }

    public function getGlobals(): array
    {
        return $this->get('globals');
    }

    public function getFunctions(): array
    {
        return $this->get('functions');
    }

    public function getFilters(): array
    {
        return $this->get('filters');
    }

    public function getExtensions(): array
    {
        return $this->get('extensions');
    }

    public function getLexer(): array
    {
        return $this->get('lexer');
    }

    public function getDate(): array
    {
        return $this->get('date');
    }

    public function getNumberFormat(): array
    {
        return $this->get('number_format');
    }

    private function objectIsCacheInterface($value): bool
    {
        if (! is_object($value)) {
            // if it's not an object we ignore this validation.
            return true;
        }

        return Validator::is($value, CacheInterface::class);
    }

    // The facades array structure should be : a string index (used as the facade name), and the value should be an array with at least an existing 'class' key.
    private function isValidFacadeArray(array $facades): bool
    {
        foreach ($facades as $key => $value) {
            if (! is_string($key)) {
                return false;
            }

            if (! is_array($value)) {
                return false;
            }

            if (! isset($value['class'])) {
                return false;
            }
        }

        return true;
    }
}
