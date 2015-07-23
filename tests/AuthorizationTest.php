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

        $slim = new \Slim\Slim();
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

        $slim = new \Slim\Slim();
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
}
