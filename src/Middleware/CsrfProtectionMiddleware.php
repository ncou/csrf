<?php

declare(strict_types=1);

namespace Chiron\Csrf\Middleware;

use Chiron\Csrf\Exception\TokenMismatchException;
use Chiron\Http\Message\RequestMethod as Method;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

//https://docs.djangoproject.com/en/1.8/ref/csrf/
//https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection.html

// Helper methodes =>
//https://codeigniter4.github.io/userguide/libraries/security.html#id2
//https://github.com/codeigniter4/CodeIgniter4/blob/7c55d73abfb206b5ed3e0dd52cea2ad6c1134975/system/Common.php#L260

//https://github.com/yiisoft/csrf/blob/master/src/CsrfMiddleware.php#L42
//https://github.com/selective-php/csrf/blob/master/src/CsrfMiddleware.php#L192

// TODO : créer une méthode [__constructor(?array $methods = null)] ou [__constructor(array $methods = self::NOT_SAFE_METHODS)] qui prendrait un array avec les request methodes à vérifier, si la valeur est nulle par défaut on utilisera le tableau self::NOT_SAFE_METHODS, cela permet de customiser le middleware. et on pourra utiliser une constante ANY si besoin (ex : new CsrfProtectionMiddleware(Method::ANY)) pour activer la protection sur les méthodes safe et unsafe à la fois.

/**
 * Provides generic CSRF protection using "Double Submit Cookie" approach.
 * An antiforgery token is required for HTTP methods other than GET, HEAD, OPTIONS, and TRACE.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie
 */
final class CsrfProtectionMiddleware implements MiddlewareInterface
{
    /**
     * Header to check for token instead of POST/GET data.
     */
    public const HEADER = 'X-CSRF-Token';

    /**
     * Parameter name used to represent client token in POST data.
     */
    public const PARAMETER = 'csrf-token';

    /**
     * {@inheritdoc}
     *
     * @throws TokenMismatchException An http 412 Precondition Failed exception.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Verify CSRF token if the request method is considered "unsafe".
        if ($this->needsProtection($request) && ! $this->tokensMatch($request)) {
            // Throw an http error 412 "pre-condition failed" exception.
            throw new TokenMismatchException();
        }

        return $handler->handle($request);
    }

    /**
     * Assume that anything not defined as 'safe' by RFC7231 needs protection.
     *
     * @param ServerRequestInterface $request
     *
     * @return bool
     */
    private function needsProtection(ServerRequestInterface $request): bool
    {
        return Method::isSafe($request->getMethod()) === false;
    }

    /**
     * Check if the csrf token from the user request match the expected token.
     *
     * @param ServerRequestInterface $request
     *
     * @return bool
     */
    private function tokensMatch(ServerRequestInterface $request): bool
    {
        $expectedToken = $this->getToken($request);
        $providedToken = $this->getTokenFromRequest($request);

        return hash_equals($expectedToken, $providedToken);
    }

    /**
     * Retrieve the token value present in the request attribute.
     * Token come from the previous middleware "CsrfTokenMiddleware".
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    private function getToken(ServerRequestInterface $request): string
    {
        $token = $request->getAttribute(CsrfTokenMiddleware::ATTRIBUTE);

        // TODO : il faudrait pas vérifier qu'il fait bien la taille attendue ??? style créer une méthode isValidToken( qui fait la vérif suivante) :    is_string($token) && ctype_alnum($token) && strlen($token) === CsrfTokenMiddleware::TOKEN_LENGTH;
        if (! $token || ! is_string($token)) {
            throw new LogicException('Unable to prepare CSRF protection, token attribute is missing or invalid.');
        }

        return $token;
    }

    /**
     * Fetch user token from the request (via header or body).
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    // TODO : appeller la méthode isValidToken() pour vérifier qui la valeur est bien une string+alnum+de taille 40 caractéres ??? EDIT : cet appel ne me semble pas nécessaire car va surement allourdir le code !!!
    private function getTokenFromRequest(ServerRequestInterface $request): string
    {
        if ($request->hasHeader(self::HEADER)) {
            return (string) $request->getHeaderLine(self::HEADER);
        }

        $body = $request->getParsedBody();

        if (is_array($body) && isset($body[self::PARAMETER]) && is_string($body[self::PARAMETER])) {
            return $body[self::PARAMETER];
        }

        return '';
    }
}
