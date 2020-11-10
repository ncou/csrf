<?php

declare(strict_types=1);

namespace Chiron\Csrf\Tests;

use Chiron\Security\Config\SecurityConfig;
use Chiron\Container\Container;
use Chiron\Security\Security;
use Chiron\Csrf\Config\CsrfConfig;
use Chiron\Csrf\Exception\InvalidTokenException;
use Chiron\Csrf\Exception\TokenMismatchException;
use Chiron\Csrf\Middleware\CsrfProtectionMiddleware;
use Chiron\Csrf\Middleware\CsrfTokenMiddleware;
use Chiron\Http\Http;
use Closure;
use LogicException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class CsrfTest extends TestCase
{
    private $container;
    private $key;

    public function setUp(): void
    {
        $this->container = new Container();
        $this->container->setAsGlobal();

        $this->key = bin2hex(random_bytes(32));

        $securityConfig = new SecurityConfig([
            'key' => $this->key,
        ]);
        $this->container->bind(SecurityConfig::class, $securityConfig);

        $csrfConfig = new CsrfConfig([
            'cookie'   => 'csrf-token',
            'length'   => 16,
            'lifetime' => 86400,
        ]);
        $this->container->bind(CsrfConfig::class, $csrfConfig);
    }

    public function testGet(): void
    {
        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write($r->getAttribute(CsrfTokenMiddleware::ATTRIBUTE));

                return $response;
            };

        $core = $this->httpCore([CsrfTokenMiddleware::class], $handler);

        $response = $this->get($core, '/');
        self::assertSame(200, $response->getStatusCode());
        // Cookie csrf-token should be presents in the response, if the request has not csrf-token cookie.
        self::assertTrue($response->hasHeader('Set-Cookie'));

        $cookies = $this->fetchCookies($response);

        self::assertArrayHasKey('csrf-token', $cookies);
        self::assertSame($cookies['csrf-token'], (string) $response->getBody());
    }

    public function testGetWithGoodCookieToken(): void
    {
        $id = Security::generateId(CsrfTokenMiddleware::TOKEN_ID_LENGTH);
        $token = $id . hash_hmac(CsrfTokenMiddleware::HASH_FUNCTION_NAME, $id, $this->key);

        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write($r->getAttribute(CsrfTokenMiddleware::ATTRIBUTE));

                return $response;
            };

        $core = $this->httpCore([CsrfTokenMiddleware::class], $handler);

        $response = $this->get($core, '/', [], [], ['csrf-token' => $token]);
        self::assertSame(200, $response->getStatusCode());
        // Cookie csrf-token should NOT be presents in the response, if the request has a valid csrf-token cookie.
        self::assertFalse($response->hasHeader('Set-Cookie'));
        self::assertSame($token, (string) $response->getBody());
    }

    public function testGetWithBadCookieToken(): void
    {
        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write($r->getAttribute(CsrfTokenMiddleware::ATTRIBUTE));

                return $response;
            };

        $core = $this->httpCore([CsrfTokenMiddleware::class], $handler);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Request to the specified resource has been aborted because CSRF token is invalid.');

        $response = $this->get($core, '/', [], [], ['csrf-token' => 'not_valid_token']);
    }

    public function testLogicException(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Unable to apply CSRF protection, attribute is missing or invalid.');

        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write('all good');

                return $response;
            };

        $core = $this->httpCore([CsrfProtectionMiddleware::class], $handler);

        $response = $this->post($core, '/');
    }

    public function testPostForbidden(): void
    {
        $this->expectException(TokenMismatchException::class);
        $this->expectExceptionMessage('Access to the specified resource has been forbidden because CSRF verification failed.');

        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write('all good');

                return $response;
            };

        $core = $this->httpCore([CsrfTokenMiddleware::class, CsrfProtectionMiddleware::class], $handler);

        $response = $this->post($core, '/');
    }

    public function testPostOK(): void
    {
        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write('all good');

                return $response;
            };

        $core = $this->httpCore([CsrfTokenMiddleware::class, CsrfProtectionMiddleware::class], $handler);

        $response = $this->get($core, '/');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('all good', (string) $response->getBody());

        $cookies = $this->fetchCookies($response);

        // use the good token (from the get cookie response) in the post request BODY/HEADER
        $response = $this->post(
            $core,
            '/',
            [
                'csrf-token' => $cookies['csrf-token'],
            ],
            [],
            [
                'csrf-token' => $cookies['csrf-token'],
            ]
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('all good', (string) $response->getBody());
    }

    public function testHeaderOK(): void
    {
        $handler = static function (ServerRequestInterface $r) {
                $response = new Response();
                $response->getBody()->write('all good');

                return $response;
            };

        $core = $this->httpCore([CsrfTokenMiddleware::class, CsrfProtectionMiddleware::class], $handler);

        $response = $this->get($core, '/');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('all good', (string) $response->getBody());

        $cookies = $this->fetchCookies($response);

        // use the good token (from the get cookie response) in the post request BODY/HEADER
        $response = $this->post(
            $core,
            '/',
            [],
            [
                'X-CSRF-Token' => $cookies['csrf-token'],
            ],
            [
                'csrf-token' => $cookies['csrf-token'],
            ]
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('all good', (string) $response->getBody());
    }

    protected function httpCore(array $middlewares = [], Closure $handler): Http
    {
        $http = new Http($this->container);

        foreach ($middlewares as $middleware) {
            $http->addMiddleware($middleware);
        }

        $http->setHandler($handler);

        return $http;
    }

    protected function get(
        Http $core,
        $uri,
        array $query = [],
        array $headers = [],
        array $cookies = []
    ): ResponseInterface {
        return $core->handle($this->request($uri, 'GET', $query, $headers, $cookies));
    }

    protected function post(
        Http $core,
        $uri,
        array $data = [],
        array $headers = [],
        array $cookies = []
    ): ResponseInterface {
        return $core->handle($this->request($uri, 'POST', [], $headers, $cookies)->withParsedBody($data));
    }

    protected function request(
        $uri,
        string $method,
        array $query = [],
        array $headers = [],
        array $cookies = []
    ): ServerRequest {
        $request = new ServerRequest($method, $uri, $headers);

        $request = $request->withQueryParams($query)->withCookieParams($cookies);

        return $request;
    }

    protected function fetchCookies(ResponseInterface $response): array
    {
        $result = [];

        foreach ($response->getHeaders() as $header) {
            foreach ($header as $headerLine) {
                $chunk = explode(';', $headerLine);
                if (! count($chunk) || mb_strpos($chunk[0], '=') === false) {
                    continue;
                }

                $cookie = explode('=', $chunk[0]);
                $result[$cookie[0]] = rawurldecode($cookie[1]);
            }
        }

        return $result;
    }
}
