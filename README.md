# Chadicus\Slim\OAuth2\Middleware

[![Build Status](https://travis-ci.org/chadicus/slim-oauth2-middleware.svg?branch=master)](https://travis-ci.org/chadicus/slim-oauth2-middleware)
[![Code Quality](https://scrutinizer-ci.com/g/chadicus/slim-oauth2-middleware/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/chadicus/slim-oauth2-middleware/?branch=master)
[![Code Coverage](https://coveralls.io/repos/github/chadicus/slim-oauth2-middleware/badge.svg?branch=master)](https://coveralls.io/github/chadicus/slim-oauth2-middleware?branch=master)
[![Dependency Status](https://www.versioneye.com/user/projects/55b9075e653762001a0012b3/badge.svg?style=flat)](https://www.versioneye.com/user/projects/55b9075e653762001a0012b3)

[![Latest Stable Version](https://poser.pugx.org/chadicus/slim-oauth2-middleware/v/stable)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)
[![Latest Unstable Version](https://poser.pugx.org/chadicus/slim-oauth2-middleware/v/unstable)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)
[![License](https://poser.pugx.org/chadicus/slim-oauth2-middleware/license)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)

[![Total Downloads](https://poser.pugx.org/chadicus/slim-oauth2-middleware/downloads)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)
[![Daily Downloads](https://poser.pugx.org/chadicus/slim-oauth2-middleware/d/daily)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)
[![Monthly Downloads](https://poser.pugx.org/chadicus/slim-oauth2-middleware/d/monthly)](https://packagist.org/packages/chadicus/slim-oauth2-middleware)

[![Documentation](https://img.shields.io/badge/reference-phpdoc-blue.svg?style=flat)](http://pholiophp.org/chadicus/slim-oauth2-middleware)

Middleware for Using OAuth2 within a Slim Framework API

## Requirements

Chadicus\Slim\OAuth2\Middleware requires PHP 5.5 (or later).

##Composer
To add the library as a local, per-project dependency use [Composer](http://getcomposer.org)! Simply add a dependency on
`chadicus/slim-oauth2-middleware` to your project's `composer.json` file such as:

```json
{
    "require": {
        "chadicus/slim-oauth2-middleware": "~1.0"
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
