# HTTP CSRF Protection - Middleware (PSR15)

PSR15 Middleware to protect your application againts [Cross-Site Request Forgery](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

[![Build Status](https://img.shields.io/travis/org/ncou/csrf/master.svg?style=flat-square)](https://travis-ci.org/ncou/csrf)
[![Latest Version](https://img.shields.io/github/release/ncou/csrf/csrf.svg?style=flat-square)](https://packagist.org/packages/ncou/csrf)
[![Total Downloads](https://img.shields.io/packagist/dt/ncou/csrf/csrf.svg?style=flat-square)](https://packagist.org/packages/ncou/csrf)

This middleware use the Cookies to store a token used for comparaison in each "unsafe" request (`POST`/`PUT`/`PATCH`/`DELETE`).

## Why?

Because.

## Installation

```bash
$ composer require chiron/csrf
```

To activate the extension:

```php
[
    //...
    XXX\CsrfBootloader::class,
]
```

The extension will activate `Chiron\Csrf\Middleware\CsrfTokenMiddleware` to issue a unique token for every user request.

## Enable Protection - Specific Route

The extension provides a middleware `CsrfProtectionMiddleware` which activates the protection on your routes (specific route or every routes). 
This middleware will protect all the requests for the "unsafe" methods `POST`, `PUT`, `PATCH`, `DELETE`.

```php
use Chiron\Csrf\Middleware\CsrfProtectionMiddleware;

// ...

public function boot(RouterInterface $router)
{
    $route = new Route('/', new Target\Action(HomeController::class, 'index'));

    $router->setRoute(
        'index',
        $route->withMiddleware(CsrfProtectionMiddleware::class)
    );
}
```

## Enable Protection - All Routes

To activate CSRF protection on all the routes, you need to "globally" register `Chiron\Csrf\Middleware\CsrfProtectionMiddleware` via `MiddlewareQueue`:

```php
use Chiron\Csrf\Middleware\CsrfProtectionMiddleware;

// ...

public function boot(MiddlewareQueue $middlewares)
{
    $middlewares->addMiddleware(CsrfProtectionMiddleware::class);
}
```

## Usage

Once the protection is activated, you must sign every request with the token available via PSR-7 attribute `csrfToken`.

To receive this token in the controller or view:

```php
public function index(ServerRequestInterface $request)
{
    $csrfToken = $request->getAttribute('csrfToken');
}
``` 

Every `POST`/`PUT`/`PATCH`/`DELETE` request from the user must include this token as POST parameter `csrf-token` or header `X-CSRF-Token`.

Users will receive an error `403 Forbidden` if a token is missing.

Users will receive an error `412 Precondition Failed` if the token has been tampered (and the cookie will be deleted).

```php
public function index(ServerRequestInterface $request)
{
    $form = '
        <form method="post">
          <input type="hidden" name="csrf-token" value="{csrfToken}"/>
          <input type="text" name="value"/>
          <input type="submit"/>
        </form>
    ';

    $form = str_replace(
        '{csrfToken}',
        $request->getAttribute('csrfToken'),
        $form
    );

    return $form;
}
```

## TODO
- Add documentation on the "csrf_token()" helper.
- Create a TwigExtension class to add the csrf_token.
