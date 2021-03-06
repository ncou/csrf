<?php

declare(strict_types=1);

namespace Chiron\Csrf\Test;

use Chiron\Http\Http;
use Closure;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

abstract class AbstractTestCase extends TestCase
{
    protected $container;

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
