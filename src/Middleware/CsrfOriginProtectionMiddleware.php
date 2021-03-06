<?php

declare(strict_types=1);

namespace Chiron\Csrf\Middleware;

use Chiron\Csrf\Config\CsrfConfig;
use Chiron\Csrf\Exception\BadOriginException;
use Chiron\Csrf\Exception\UntrustedOriginException;
use Chiron\Http\Helper\Uri;
use Chiron\Http\Message\RequestMethod as Method;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

//https://github.com/Pylons/pyramid/blob/ee7ca28cc51cf40d1190144834704e287c9fc72d/src/pyramid/csrf.py#L248
//https://github.com/django/django/blob/5fcfe5361e5b8c9738b1ee4c1e9a6f293a7dda40/django/middleware/csrf.py#L224

/**
 * Check the 'Origin' of the request to see if it is a cross site request
 * or not.
 * If the value supplied by the 'Origin' or 'Referer' header isn't one of
 * the trusted origins and 'raises' is 'True', this function will raise a
 * :exc:`pyramid.exceptions.BadCSRFOrigin` exception, but if 'raises' is
 * 'False', this function will return 'False' instead. If the CSRF origin
 * checks are successful this function will return 'True' unconditionally.
 * Additional trusted origins may be added by passing a list of domain (and
 * ports if non-standard like '['example.com', 'dev.example.com:8080']'') in
 * with the 'trusted_origins' parameter. If 'trusted_origins' is 'None'
 * (the default) this list of additional domains will be pulled from the
 * 'pyramid.csrf_trusted_origins' setting.
 * 'allow_no_origin' determines whether to return 'True' when the
 * origin cannot be determined via either the 'Referer' or 'Origin'
 * header. The default is 'False' which will reject the check.
 *
 * Note that this function will do nothing if 'request.scheme' is not
 * 'https'.
 */
// TODO : tester en ajoutant plusieurs fois le Referer Header dans la request !!!!
final class CsrfOriginProtectionMiddleware implements MiddlewareInterface
{
    /** @var array */
    private $csrfConfig;

    /**
     * @param HttpConfig     $httpConfig
     * @param SettingsConfig $settingsConfig
     */
    public function __construct(CsrfConfig $csrfConfig)
    {
        $this->csrfConfig = $csrfConfig;
    }

    // Suppose user visits http://example.com/
    // An active network attacker (man-in-the-middle, MITM) sends a
    // POST form that targets https://example.com/detonate-bomb/ and
    // submits it via JavaScript.
    //
    // The attacker will need to provide a CSRF cookie and token, but
    // that's no problem for a MITM when we cannot make any assumptions
    // about what kind of session storage is being used. So the MITM can
    // circumvent the CSRF protection. This is true for any HTTP connection,
    // but anyone using HTTPS expects better! For this reason, for
    // https://example.com/ we need additional protection that treats
    // http://example.com/ as completely untrusted. Under HTTPS,
    // Barth et al. found that the Referer header is missing for
    // same-domain requests in only about 0.2% of cases or less, so
    // we can use strict Referer checking.
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Origin checks are only trustworthy on HTTPS requests.
        if ($this->needsProtection($request) && $this->isRequestSecure($request)) {
            // Use the 'referer' header as origin.
            $referer = $this->parseRefererHeader($request);
            // Trusted origins list also contains the current host.
            $trustedOrigins = $this->getTrustedOrigins($request);

            if (! $this->isTrustedOrigin($referer['host'], $trustedOrigins)) {
                // Throw an http error 412 "pre-condition failed" exception.
                throw new UntrustedOriginException($referer['url']);
            }
        }

        $response = $handler->handle($request);

        return $response;
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
    // TODO : ajouter cette méthode dans un Trait ???? car elle est aussi utilisée dans une autre class pour la protection csrf !!!
    private function needsProtection(ServerRequestInterface $request): bool
    {
        return Method::isSafe($request->getMethod()) === false;
    }

    /**
     * Check if the request is an HTTP Secure.
     *
     * @param ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecure(ServerRequestInterface $request): bool
    {
        return $request->getUri()->getScheme() === 'https';
    }

    private function parseRefererHeader(ServerRequestInterface $request): array
    {
        $value = $request->getHeaderLine('Referer');

        if ($value === '') {
            throw new BadOriginException('no Referer.');
        }

        // The parts ('scheme', 'host'...etc) could have the values 'null' or 'false' for invalid url.
        $result = parse_url($value);

        // Make sure we have a valid URL for Referer.
        if (! is_string($result['host'])) {
            throw new BadOriginException('Referer is malformed.');
        }
        if (! is_string($result['scheme'])) {
            throw new BadOriginException('Referer is malformed.');
        }

        // Ensure that our Referer is also secure.
        if ($result['scheme'] !== 'https') {
            throw new BadOriginException('Referer is insecure while host is secure.');
        }

        // Add the full referer value in the result array.
        $result['url'] = $value;

        return $result;
    }

    private function getTrustedOrigins(ServerRequestInterface $request): array
    {
        $trustedOrigins = $this->csrfConfig->getTrustedOrigins();

        // Method getHost() includes the port.
        $host = $this->getHost($request);

        // TODO : vérifier l'utilité de ce if $host === '' car je ne sais pas si ce cas peut arriver, et comment ca fonctionne si on ajoute d'officie le host vide dans le tableau comment va se comporter la méthode isSameDomain ????
        if ($host !== '') {
            $trustedOrigins[] = $host;
        }

        return $trustedOrigins;
    }

    /**
     * Returns the HTTP host + port (if it's non-standard).
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    private function getHost(ServerRequestInterface $request): string
    {
        $host = $request->getUri()->getHost();
        if ($host === '') {
            return '';
        }
        // Standard ports are null (80, 443)
        $port = $request->getUri()->getPort();
        if ($port !== null) {
            $host .= ':' . $port;
        }

        return $host;
    }

    private function isTrustedOrigin(string $origin, array $trustedOrigins): bool
    {
        // Check if the request's origin matches any of our trusted origins.
        foreach ($trustedOrigins as $pattern) {
            if (Uri::isSameDomain($origin, $pattern)) {
                return true;
            }
        }

        return false;
    }
}
