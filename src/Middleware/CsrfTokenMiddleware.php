<?php

declare(strict_types=1);

namespace Chiron\Csrf\Middleware;

use Chiron\Csrf\Config\CsrfConfig;
use Chiron\Cookies\Cookie;
use Chiron\Security\Config\SecurityConfig;
use Chiron\Security\Security;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

//https://github.com/cakephp/cakephp/blob/master/src/Http/Middleware/CsrfProtectionMiddleware.php
////https://github.com/Riimu/Kit-CSRF/blob/master/src/CSRFHandler.php#L202

//https://github.com/cakephp/cakephp/blob/master/src/Http/Middleware/CsrfProtectionMiddleware.php

//https://github.com/laravel/framework/blob/43bea00fd27c76c01fd009e46725a54885f4d2a5/src/Illuminate/Foundation/Http/Middleware/VerifyCsrfToken.php

// TODO : gérer le 'path' dans le cookie header. cf //'path' => $request->getAttribute('webroot'), // https://github.com/cakephp/cakephp/blob/master/src/Http/Middleware/CsrfProtectionMiddleware.php#L331
// TODO : attention à bien gérer le basePath => https://github.com/spiral/framework/blob/aad9e94182cc819201ab0206da6078a0e1c33130/src/AuthHttp/src/Transport/CookieTransport.php#L95

// TODO : il faudrait pas faire une vérification au début de la méthode process que l'attribut 'static::ATTRIBUTE' de la request n'est pas déjà présent ??? et dans ce cas lever une erreur car cela signifie qu'on a enregister deux fois le middleware dans la stack (ou alors empécher l'ajout du même middleware plusieurs fois dans le pipeline) !!!! ex : https://github.com/cakephp/cakephp/blob/master/src/Http/Middleware/CsrfProtectionMiddleware.php#L127

/**
 * Provides generic CSRF protection using "Double Submit Cookie" approach.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie
 */
final class CsrfTokenMiddleware implements MiddlewareInterface
{
    /**
     * Request attribute name used to store the token value used later.
     */
    public const ATTRIBUTE = 'csrfToken';

    /**
     * Length of the token.
     */
    public const TOKEN_LENGTH = 40;

    /** @var string */
    private $secretKey;

    /** @var CsrfConfig */
    private $csrfConfig;

    /**
     * @param SecurityConfig $securityConfig
     * @param CsrfConfig     $csrfConfig
     */
    // TODO : utiliser le champ length pour paramétrer la longeur du token_id qui sera utilisé !!!
    public function __construct(SecurityConfig $securityConfig, CsrfConfig $csrfConfig) // TODO : ajouter le httpConfig et stocker dans une variable de classe le $this->basePath
    {
        // Secret key (32 bytes) will be used to sign the token.
        $this->secretKey = $securityConfig->getRawKey();
        $this->csrfConfig = $csrfConfig;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Try to retrieve an existing token from the cookie request.
        $token = $this->getTokenFromCookie($request);

        // If it doesn't exist, prepare a csrf token and the cookie to store it.
        if ($token === null) {
            $token = $this->generateToken();
            $cookie = $this->prepareCookie($token);
        }

        // CSRF issues must be handled by the CsrfProtection middleware.
        $response = $handler->handle($request->withAttribute(static::ATTRIBUTE, $token));
        // Attach the token cookie for the "futur" request call.
        if (isset($cookie)) {
            $response = $response->withAddedHeader('Set-Cookie', $cookie->toHeaderValue());
        }

        return $response;
    }

    /**
     * Get the token from the request cookie if it's present.
     * Unsign the cookie token value using the secret key.
     * Return null if the cookie is missing or if the cookie value is not a string or if the unsign fail.
     *
     * @param string $token The CSRF token.
     *
     * @return string|null
     */
    private function getTokenFromCookie(ServerRequestInterface $request): ?string
    {
        $cookieName = $this->csrfConfig->getCookie();
        $token = $request->getCookieParams()[$cookieName] ?? null;

        // TODO : code pas très beau !!! à améliorer.
        if (! is_string($token)) {
            return null;
        }

        return Security::unsign($token, $this->secretKey) ?: null;
    }

    /**
     * Generate a token to be used for CSRF protection.
     *
     * @return string
     */
    private function generateToken(): string
    {
        return Security::generateId(self::TOKEN_LENGTH);
    }

    /**
     * Create CSRF cookie with the signed token value.
     *
     * @param string $token
     *
     * @return Cookie
     */
    private function prepareCookie(string $token): Cookie
    {
        // TODO : core à améliorer, éventuellement mettre une ligne de code pour récupérer le $name, une autre ligne pour le signed Token dans une variable $value, et une pour les $options et une derniére ligne avec un return Cookie::create($name, $value, $options);
        $cookie = Cookie::create(
            $this->csrfConfig->getCookie(),
            Security::sign($token, $this->secretKey),
            [
                'expires'  => time() + $this->csrfConfig->getCookieLifetime(),
                //'path' => null, //'path' => $request->getAttribute('webroot'), // https://github.com/cakephp/cakephp/blob/master/src/Http/Middleware/CsrfProtectionMiddleware.php#L331
                'secure'   => $this->csrfConfig->isCookieSecure(),
                'samesite' => $this->csrfConfig->getSameSite(),
                'httponly' => true,
            ]
        );

        return $cookie;
    }
}
