<?php

declare(strict_types=1);

namespace Chiron\Csrf\Middleware;

use Chiron\Cookies\Cookie;
use Chiron\Cookies\CookieFactory;
use Chiron\Csrf\Config\CsrfConfig;
use Chiron\Security\Exception\BadSignatureException;
use Chiron\Security\Signer;
use Chiron\Security\Support\Random;
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
    public const ATTRIBUTE = 'csrfToken'; // TODO : utiliser la valeur '__csrfToken__' ???

    /**
     * Length of the token.
     */
    public const TOKEN_LENGTH = 40;

    /** @var CsrfConfig */
    private $csrfConfig;

    /** @var CookieFactory */
    private $cookieFactory;

    /** @var Signer */
    private $signer;

    /**
     * @param CsrfConfig    $csrfConfig
     * @param CookieFactory $cookieFactory
     * @param Signer        $signer
     */
    public function __construct(CsrfConfig $csrfConfig, CookieFactory $cookieFactory, Signer $signer)
    {
        $this->csrfConfig = $csrfConfig;
        $this->cookieFactory = $cookieFactory;
        // Use the class name as salt to have a different signatures in different application module.
        $this->signer = $signer->withSalt(self::class);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Retrieve an existing token from the cookie or generate a new one.
        $token = $this->prepareToken($request);

        // CSRF issues must be handled by the CsrfProtection middleware.
        $response = $handler->handle($request->withAttribute(static::ATTRIBUTE, $token));

        // Attach/Refresh the token cookie for the "next" request call.
        $cookie = $this->createCookie($token);

        return $response->withAddedHeader('Set-Cookie', (string) $cookie); // TODO : créer une méthode return $this->withCsrfTokenCookie($response, $token):ResponseInterface qui se charge d'attacher le cookie à la réponse et à retourner le nouvel objet $response actualisé.
    }

    /**
     * Return the token found in the cookie, or generate a new one.
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    private function prepareToken(ServerRequestInterface $request): string
    {
        // Try to retrieve an existing token from the cookie request.
        $token = $this->getTokenFromCookie($request->getCookieParams());

        // If token isn't present in the cookie, we generate a new token.
        if ($token === null) {
            $token = $this->generateToken();
        }

        return $token;
    }

    /**
     * Get the token from the request cookie if it's present.
     * Unsign the cookie token value using the app secret key.
     *
     * Return null if the cookie is missing or if the unsign fail.
     *
     * @param array $cookies
     *
     * @return string|null
     */
    private function getTokenFromCookie(array $cookies): ?string
    {
        $name = $this->csrfConfig->getCookieName();
        $value = $cookies[$name] ?? '';

        try {
            return $this->signer->unsign($value);
        } catch (BadSignatureException $e) {
            // Don't blow up the middleware if the signature is invalid.
            return null;
        }
    }

    /**
     * Generate a random id used as token for CSRF protection.
     *
     * @return string
     */
    private function generateToken(): string
    {
        return Random::alphanum(self::TOKEN_LENGTH);
    }

    /**
     * Create CSRF cookie to store the signed token value.
     *
     * Sign the value for better security (in case of XSS attack).
     *
     * @param string $token
     *
     * @return Cookie
     */
    private function createCookie(string $token): Cookie
    {
        $name = $this->csrfConfig->getCookieName();
        $value = $this->signer->sign($token);
        $expires = time() + $this->csrfConfig->getCookieAge();

        return $this->cookieFactory->create($name, $value, $expires);
    }
}
