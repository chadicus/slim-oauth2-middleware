<?php

namespace ChadicusTest\Slim\OAuth2\Middleware;

use ArrayObject;
use Chadicus\Slim\OAuth2\Middleware\Authorization;
use OAuth2;
use OAuth2\Storage;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Middleware\Authorization class.
 *
 * @coversDefaultClass \Chadicus\Slim\OAuth2\Middleware\Authorization
 * @covers ::<private>
 * @covers ::__construct
 */
final class AuthorizationTest extends \PHPUnit\Framework\TestCase
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

        $middleware = new Authorization($server);
        $next = $this->getNext(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ]
        );

        $middleware($request, new Response(), $next);
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

        $middleware = new Authorization($server);

        $next = function () {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            '{"error":"invalid_token","error_description":"The access token provided has expired"}',
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

        $middleware = new Authorization($server);

        $next = $this->getNext(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'allowFoo anotherScope',
            ]
        );

        $response = $middleware->withRequiredScope(['allowFoo'])->__invoke($request, new Response(), $next);
        $this->assertSame(200, $response->getStatusCode());
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

        $middleware = new Authorization($server, ['allowFoo']);

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

        $middleware = new Authorization($server);

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

        $middleware = new Authorization($server, ['superUser', ['basicUser', 'withPermission']]);

        $next = $this->getNext(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'basicUser withPermission anExtraScope',
            ]
        );

        $response = $middleware($request, new Response(), $next);
        $this->assertSame(200, $response->getStatusCode());
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

        $middleware = new Authorization($server, []);

        $next = $this->getNext(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ]
        );

        $middleware($request, new Response(), $next);
    }

    /**
     * Verify Content-Type header is added to response.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeAddsContentType()
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

        $middleware = new Authorization($server);

        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware($request, new Response(), $next);

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Verify Content-Type header remains unchanged if OAuth2 response contains the header.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeRetainsContentType()
    {
        $oauth2ServerMock = $this->getMockBuilder('\\OAuth2\\Server')->disableOriginalConstructor()->getMock();
        //always return false on verify
        $oauth2ServerMock->method('verifyResourceRequest')->willReturn(false);
        //return a valid response with Content-Type
        $oauth2ServerMock->method('getResponse')->willReturn(
            new OAuth2\Response([], 400, ['Content-Type' => 'text/html'])
        );

        $middleware = new Authorization($oauth2ServerMock);
        $next = function ($request, $response) {
            throw new \Exception('This will not get executed');
        };

        $response = $middleware(new ServerRequest(), new Response(), $next);
        $this->assertSame('text/html', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Verify basic behavior of process()
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function process()
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

        $middleware = new Authorization($server);

        $handler = $this->getRequestHandler(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ]
        );

        $middleware->process($request, $handler);
    }

    /**
     * Verify behavior of process() with expired access token.
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function processExpiredToken()
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

        $middleware = new Authorization($server);

        $response = $middleware->process($request, $this->getRequestHandler());

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            '{"error":"invalid_token","error_description":"The access token provided has expired"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify basic behaviour of withRequiredScope().
     *
     * @test
     * @covers ::process
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function processWithRequiredScope()
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

        $middleware = new Authorization($server);

        $handler = $this->getRequestHandler(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'allowFoo anotherScope',
            ]
        );

        $response = $middleware->withRequiredScope(['allowFoo'])->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * Verify behaviour of withRequiredScope() with insufficient scope.
     *
     * @test
     * @covers ::process
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function processWithRequiredScopeInsufficientScope()
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

        $middleware = new Authorization($server, ['allowFoo']);
        $response = $middleware->process($request, $this->getRequestHandler());

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided '
            . 'by the access token"}',
            (string)$response->getBody()
        );
    }

    /**
     * Verify behavior of process() without access token.
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function processNoTokenProvided()
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

        $middleware = new Authorization($server);
        $response = $middleware->process($request, $this->getRequestHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * Verify process() with scopes using OR logic
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function processWithEitherScope()
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

        $middleware = new Authorization($server, ['superUser', ['basicUser', 'withPermission']]);

        $handler = $this->getRequestHandler(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'basicUser withPermission anExtraScope',
            ]
        );

        $response = $middleware->process($request, $handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * Verify behavior of the middleware with empty scope
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function processWithEmptyScope()
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

        $middleware = new Authorization($server, []);

        $handler = $this->getRequestHandler(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ]
        );

        $middleware->process($request, $handler);
    }

    /**
     * Verify Content-Type header is added to response.
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function processAddsContentType()
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

        $middleware = new Authorization($server);
        $response = $middleware->process($request, $this->getRequestHandler());

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Verify Content-Type header remains unchanged if OAuth2 response contains the header.
     *
     * @test
     * @covers ::process
     *
     * @return void
     */
    public function processRetainsContentType()
    {
        $oauth2ServerMock = $this->getMockBuilder('\\OAuth2\\Server')->disableOriginalConstructor()->getMock();
        //always return false on verify
        $oauth2ServerMock->method('verifyResourceRequest')->willReturn(false);
        //return a valid response with Content-Type
        $oauth2ServerMock->method('getResponse')->willReturn(
            new OAuth2\Response([], 400, ['Content-Type' => 'text/html'])
        );

        $middleware = new Authorization($oauth2ServerMock);
        $response = $middleware->process(new ServerRequest(), $this->getRequestHandler());

        $this->assertSame('text/html', $response->getHeaderLine('Content-Type'));
    }

    private function getNext(array $token) : callable
    {
        $test = $this;
        return function (
            ServerRequestInterface $request,
            ResponseInterface $response
        ) use (
            $test,
            $token
        ) : ResponseInterface {
            $test->assertSame($token, $request->getAttribute('oauth2-token'));
            return $response;
        };
    }

    private function getRequestHandler(array $token = null) : RequestHandlerInterface
    {
        $test = $this;
        $callback = function (ServerRequestInterface $request) use ($test, $token) : ResponseInterface {
            if ($token !== null) {
                $test->assertSame($token, $request->getAttribute('oauth2-token'));
            }

            return new Response();
        };

        $mock = $this->getMockBuilder('\\Psr\\Http\\Server\\RequestHandlerInterface')->getMock();
        $mock->method('handle')->willReturnCallback($callback);
        return $mock;
    }
}
