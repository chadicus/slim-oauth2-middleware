<?php

namespace Chadicus\Slim\OAuth2\Middleware;

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
     * Verify basic behavior of call()
     *
     * @test
     * @covers ::call
     *
     * @return void
     */
    public function call()
    {
        $storage = new \OAuth2\Storage\Memory(
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

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        \Slim\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'PATH_INFO' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $slim->get('/foo', function() {});
        $slim->add(new Authorization($server));

        $env = \Slim\Environment::getInstance();
        $slim->request = new \Slim\Http\Request($env);
        $slim->request->headers->set('Authorization', 'Bearer atokenvalue');
        $slim->response = new \Slim\Http\Response();

        $slim->run();
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ],
            $slim->token
        );
    }

    /**
     * Verify behavior of call with expired access token
     *
     * @test
     * @covers ::call
     *
     * @return void
     */
    public function callExpiredToken()
    {
        $storage = new \OAuth2\Storage\Memory(
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

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        \Slim\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'PATH_INFO' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $slim->get('/foo', function() {});
        $slim->add(new Authorization($server));

        $env = \Slim\Environment::getInstance();
        $slim->request = new \Slim\Http\Request($env);
        $slim->request->headers->set('Authorization', 'Bearer atokenvalue');
        $slim->response = new \Slim\Http\Response();

        ob_start();

        $slim->run();

        $json = ob_get_clean();

        $this->assertSame(401, $slim->response->status());
        $this->assertSame('{"error":"expired_token","error_description":"The access token provided has expired"}', $json);
        $this->assertSame('{"error":"expired_token","error_description":"The access token provided has expired"}', $slim->response->body());
    }

    /**
     * Verify basic behaviour of withRequiredScope().
     *
     * @test
     * @covers ::call
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function withRequiredScope()
    {
        $storage = new \OAuth2\Storage\Memory(
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

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        \Slim\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'PATH_INFO' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($server);
        $authorization->setApplication($slim);
        $slim->get('/foo', $authorization->withRequiredScope(['allowFoo']), function() {});

        $env = \Slim\Environment::getInstance();
        $slim->request = new \Slim\Http\Request($env);
        $slim->request->headers->set('Authorization', 'Bearer atokenvalue');
        $slim->response = new \Slim\Http\Response();

        ob_start();

        $slim->run();

        ob_get_clean();

        $this->assertSame(200, $slim->response->status());
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'allowFoo anotherScope',
            ],
            $slim->token
        );
    }

    /**
     * Verify behaviour of withRequiredScope() with insufficient scope.
     *
     * @test
     * @covers ::call
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function withRequiredScopeInsufficientScope()
    {
        $storage = new \OAuth2\Storage\Memory(
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

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        \Slim\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'PATH_INFO' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($server);
        $authorization->setApplication($slim);
        $slim->get('/foo', $authorization->withRequiredScope(['allowFoo']), function() {});

        $env = \Slim\Environment::getInstance();
        $slim->request = new \Slim\Http\Request($env);
        $slim->request->headers->set('Authorization', 'Bearer atokenvalue');
        $slim->response = new \Slim\Http\Response();

        ob_start();

        $slim->run();

        ob_get_clean();

        $this->assertSame(403, $slim->response->status());
        $this->assertSame(
            '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided by the access token"}',
            $slim->response->body()
        );
    }

    /**
     * Verify Authorization is invokeable.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invoke()
    {
        $storage = new \OAuth2\Storage\Memory(
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

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        \Slim\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'PATH_INFO' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($server);
        $authorization->setApplication($slim);
        $slim->get('/foo', $authorization, function() {});

        $env = \Slim\Environment::getInstance();
        $slim->request = new \Slim\Http\Request($env);
        $slim->request->headers->set('Authorization', 'Bearer atokenvalue');
        $slim->response = new \Slim\Http\Response();

        ob_start();

        $slim->run();

        ob_get_clean();

        $this->assertSame(200, $slim->response->status());
    }

    /**
     * Helper method to return a new instance of \Slim\Slim.
     *
     * @return \Slim\Slim
     */
    private static function getSlimInstance()
    {
        return new \Slim\Slim(
            [
                'version' => '0.0.0',
                'debug' => false,
                'mode'=> 'testing'
            ]
        );
    }
}
