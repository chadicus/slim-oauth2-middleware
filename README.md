# Chadicus\Slim\OAuth2\Middleware

[![Build Status](https://travis-ci.org/chadicus/slim-oauth2-middleware.svg?branch=master)](https://travis-ci.org/chadicus/slim-oauth2-middleware)
[![Scrutinizer Code Quality](http://img.shields.io/scrutinizer/g/chadicus/slim-oauth2-middleware.svg?style=flat)](https://scrutinizer-ci.com/g/chadicus/slim-oauth2-middleware/)
[![Coverage Status](https://coveralls.io/repos/chadicus/slim-oauth2-middleware/badge.svg?branch=master&service=github)](https://coveralls.io/github/chadicus/slim-oauth2-middleware?branch=master)

[![Latest Stable Version](http://img.shields.io/packagist/v/chadicus/slim-oauth2-middleware.svg?style=flat)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)
[![Total Downloads](http://img.shields.io/packagist/dt/chadicus/slim-oauth2-middleware.svg?style=flat)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)
[![License](http://img.shields.io/packagist/l/chadicus/slim-oauth2-middleware.svg?style=flat)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)

[![Dependency Status](https://www.versioneye.com/user/projects/55b9075e653762001a0012b3/badge.svg?style=flat)](https://www.versioneye.com/user/projects/55b9075e653762001a0012b3)

[![Documentation](https://img.shields.io/badge/reference-phpdoc-blue.svg?style=flat)](http://pholiophp.org/chadicus/slim-oauth2-middleware)

Middleware for Using OAuth2 within a Slim Framework API

## Requirements

Chadicus\Slim\OAuth2\Middleware requires PHP 5.4 (or later).

##Composer
To add the library as a local, per-project dependency use [Composer](http://getcomposer.org)! Simply add a dependency on
`chadicus/slim-oauth2-middleware` to your project's `composer.json` file such as:

```json
{
    "require": {
        "chadicus/slim-oauth2-middleware": "dev-master"
    }
}
```

##Contact
Developers may be contacted at:

 * [Pull Requests](https://github.com/chadicus/slim-oauth2-middleware/pulls)
 * [Issues](https://github.com/chadicus/slim-oauth2-middleware/issues)

##Project Build
With a checkout of the code get [Composer](http://getcomposer.org) in your PATH and run:

```sh
./composer install
./vendor/bin/phpunit
```

##Example Usage

Simple example for using the authorization middleware.

```php
use Chadicus\Slim\OAuth2\Middleware;
use OAuth2\Server;
use OAuth2\Storage;
use OAuth2\GrantType;
use Slim\Slim;

//set up storage for oauth2 server
$storage = new Storage\Memory(
    [
        'client_credentials' => [
            'testClientId' => [
                'client_id' => 'chadicus-app',
                'client_secret' => 'password',
            ],
        ],
    ]
);

// create the oauth2 server
$server = new Server(
    $storage,
    [
        'access_lifetime' => 3600,
    ],
    [
        new GrantType\ClientCredentials($storage),
    ]
);

// create the authorization middlware
$authorization = new Middleware\Authorization($server);

$app = new Slim();

//Assumes token endpoints available for creating access tokens

$app->get('foos', $authorization, function () {
    //return all foos, no scope required
});

$app->get('foos/id', $authorization->withRequiredScope(['superUser', ['basicUser', 'canViewFoos']]), function ($id) {
    //return details for a foo, requires superUser scope OR basicUser with canViewFoos scope
});

$app->post('foos', $authorization->withRequiredScope(['superUser']), function () {
    //Create a new foo, requires superUser scope
});
```
