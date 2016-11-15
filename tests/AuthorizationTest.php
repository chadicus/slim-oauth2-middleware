<?php

namespace Chadicus\Slim\OAuth2\Middleware;

use ArrayObject;
use OAuth2;
use OAuth2\Storage;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Middleware\Authorization class.
 *
 * @coversDefaultClass \Chadicus\Slim\OAuth2\Middleware\Authorization
 * @covers ::<private>
 * @covers ::__construct
 */
final class AuthorizationTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Verify basic behavior of __invoke()
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invoke()
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state' => true,
                'allow_implicit' => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container);

        $next = function ($request, $response) {
            return $response;
        };

        $middleware($request, new Response(), $next);

        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ],
            $container['token']
        );
    }

    /**
     * Verify behavior of __invoke() with expired access token.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeExpiredToken()
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => strtotime('-1 minute'),
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $middleware = new Authorization($server, new ArrayObject);

        $next = function () {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            '{"error":"expired_token","error_description":"The access token provided has expired"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify basic behaviour of withRequiredScope().
     *
     * @test
     * @covers ::__invoke
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function withRequiredScope()
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'allowFoo anotherScope',
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container);

        $next = function ($request, $response) {
            return $response;
        };

        $response = $middleware->withRequiredScope(['allowFoo'])->__invoke($request, new Response(), $next);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'allowFoo anotherScope',
            ],
            $container['token']
        );
    }

    /**
     * Verify behaviour of withRequiredScope() with insufficient scope.
     *
     * @test
     * @covers ::__invoke
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function withRequiredScopeInsufficientScope()
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'aScope anotherScope',
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $middleware = new Authorization($server, new ArrayObject(), ['allowFoo']);

        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided '
            . 'by the access token"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify behavior of __invoke() without access token.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeNoTokenProvided()
    {
        $storage = new Storage\Memory([]);

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', []);

        $middleware = new Authorization($server, new ArrayObject());

        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * Verify __invoke() with scopes using OR logic
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeWithEitherScope()
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'basicUser withPermission anExtraScope',
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container, ['superUser', ['basicUser', 'withPermission']]);

        $next = function ($request, $response) {
            return $response;
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'basicUser withPermission anExtraScope',
            ],
            $container['token']
        );
    }

    /**
     * Verify behavior of the middleware with empty scope
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeWithEmptyScope()
    {
        $storage = new Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new OAuth2\Server(
            $storage,
            [
                'enforce_state' => true,
                'allow_implicit' => false,
                'access_lifetime' => 3600
            ]
        );

        $uri = 'localhost:8888/foos';
        $headers = ['Authorization' => ['Bearer atokenvalue']];
        $request = new ServerRequest([], [], $uri, 'PATCH', 'php://input', $headers);

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container, []);

        $next = function ($request, $response) {
            return $response;
        };

        $middleware($request, new Response(), $next);

        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ],
            $container['token']
        );
    }

}
