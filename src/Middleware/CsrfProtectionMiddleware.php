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
 * @see https://tools.ietf.org/html/rfc7231#section-4.2.1
 */
// TODO : renommer cette classe en CsrfTokenProtectionMiddleware ???
final class CsrfProtectionMiddleware implements MiddlewareInterface
{
    /**
     * Header to check for token instead of POST/GET data.
     */
    public const HEADER = 'X-CSRF-Token'; // TODO : paramétrer ces valeurs dans le fichier csrf.php avec un champ headerName/fieldName ????

    /**
     * Parameter name used to represent client token in POST data.
     */
    public const PARAMETER = 'csrf-token'; // TODO : paramétrer ces valeurs dans le fichier csrf.php avec un champ headerName/fieldName ???? Attention vérifier si ce champ n'est pas utilisé dans la méthode csrf_token ou dans le twig extension, car si on enléve le format de constante public on devra récupérer l'objet csrfConfig et ca peut vite complexifier le code !!!!

    /**
     * {@inheritdoc}
     *
     * @throws TokenMismatchException An http 412 Precondition Failed exception.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Verify token if the request method is "unsafe" and require protection.
        if ($this->needsProtection($request) && ! $this->tokensMatch($request)) {
            // Throw an http error 412 "pre-condition failed" exception.
            throw new TokenMismatchException();
        }

        return $handler->handle($request);
    }

    /**
     * Assume that any method not defined as 'safe' by RFC7231 needs protection.
     *
     * @see https://tools.ietf.org/html/rfc7231#section-4.2.1
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
        $expected = $this->fetchToken($request);
        $provided = $this->getTokenFromRequest($request);

        return hash_equals($expected, $provided);
    }

    /**
     * Fetch the token value present in the request attribute.
     * Token come from the previous middleware "CsrfTokenMiddleware".
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    private function fetchToken(ServerRequestInterface $request): string
    {
        $token = $request->getAttribute(CsrfTokenMiddleware::ATTRIBUTE);

        // Ensure the token stored previously by the CsrfTokenMiddleware is present and has a valid format.
        if (is_string($token) && ctype_alnum($token) && strlen($token) === CsrfTokenMiddleware::TOKEN_LENGTH) {
            return $token;
        }

        throw new LogicException('Unable to prepare CSRF protection, token attribute is missing or invalid.');
    }

    /**
     * Fetch user token from the request (via header or body).
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    // TODO : vérifier si la méthode de la request est POST dans ce cas vérifier dans le body, si le token n'est pas trouvé alors regarder dans le header.
    // https://github.com/django/django/blob/master/django/middleware/csrf.py#L295
    // TODO : rendre ce code plus propre ????
    private function getTokenFromRequest(ServerRequestInterface $request): string
    {
        //$provided = $request->getParsedBody()['csrfToken'] ?? $request->getHeaderLine('X-CSRF-Token');

        if ($request->hasHeader(self::HEADER)) {
            return (string) $request->getHeaderLine(self::HEADER); // TODO : attention ca va pas poser un soucis si il y a plusieurs headers ??? on va surement avoir une string avec un ";" comme séparateur !!!!
        }

        // Handle the case for a POST form.
        $body = $request->getParsedBody();
        if (is_array($body) && isset($body[self::PARAMETER]) && is_string($body[self::PARAMETER])) {
            return $body[self::PARAMETER];
        }

        // TODO : initialiser plutot en début de méthode une variable $token = '' et ensuite la remplir soit avec le header soit avec le body (donc virer les 2 return) et finir par un return $token; en fin de méthode.
        return ''; // TODO : créer une constante privé style self::EMPTY_TOKEN qui serait une chaine vide ????
    }
}
