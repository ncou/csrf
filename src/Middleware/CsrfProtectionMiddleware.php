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

// Helper methodes =>
//https://codeigniter4.github.io/userguide/libraries/security.html#id2
//https://github.com/codeigniter4/CodeIgniter4/blob/7c55d73abfb206b5ed3e0dd52cea2ad6c1134975/system/Common.php#L260

//https://github.com/yiisoft/csrf/blob/master/src/CsrfMiddleware.php#L42
//https://github.com/selective-php/csrf/blob/master/src/CsrfMiddleware.php#L192

// TODO : créer une méthode [__constructor(?array $methods = null)] ou [__constructor(array $methods = self::NOT_SAFE_METHODS)] qui prendrait un array avec les request methodes à vérifier, si la valeur est nulle par défaut on utilisera le tableau self::NOT_SAFE_METHODS, cela permet de customiser le middleware. et on pourra utiliser une constante ANY si besoin (ex : new CsrfProtectionMiddleware(Method::ANY)) pour activer la protection sur les méthodes safe et unsafe à la fois.

/**
 * Provides generic CSRF protection using cookie as token storage. Set "csrfToken" attribute to request.
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
     * Methods who needs protection agains CSRF (should have a CSRF token attached to the request).
     */
    public const NOT_SAFE_METHODS = [Method::POST, Method::PUT, Method::PATCH, Method::DELETE];

    /**
     * {@inheritdoc}
     *
     * @throws TokenMismatchException An http 403 Forbidden exception.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->getToken($request);

        if ($this->isTokenRequired($request) && ! hash_equals($token, $this->fetchToken($request))) {
            // Throw an Http 403 Forbidden exception.
            throw new TokenMismatchException();
        }

        return $handler->handle($request);
    }

    /**
     * Retrieve the token value present in the request attribute.
     * Data come from the previous middleware "CsrfTokenMiddleware".
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    private function getToken(ServerRequestInterface $request): string
    {
        $token = $request->getAttribute(CsrfTokenMiddleware::ATTRIBUTE);

        if (! $token || ! is_string($token)) {
            throw new LogicException('Unable to apply CSRF protection, attribute is missing or invalid.');
        }

        return $token;
    }

    /**
     * Check if middleware should validate csrf token.
     *
     * @param ServerRequestInterface $request
     *
     * @return bool
     */
    private function isTokenRequired(ServerRequestInterface $request): bool
    {
        return in_array(strtoupper($request->getMethod()), self::NOT_SAFE_METHODS);
    }

    /**
     * Fetch token from request.
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    private function fetchToken(ServerRequestInterface $request): string
    {
        if ($request->hasHeader(self::HEADER)) {
            $headers = $request->getHeader(self::HEADER);

            return reset($headers); // TODO : attention la méthode reset() peut renvoyer false !!!! donc le typehint de cette méthode n'est pas correct !!!!
        }

        $data = $request->getParsedBody();

        if (is_array($data) && isset($data[self::PARAMETER]) && is_string($data[self::PARAMETER])) {
            return $data[self::PARAMETER];
        }

        return '';
    }
}
