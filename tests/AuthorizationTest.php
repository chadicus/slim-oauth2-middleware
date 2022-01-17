<?php

namespace ChadicusTest\Slim\OAuth2\Middleware;

use ArrayObject;
use Chadicus\Slim\OAuth2\Middleware\Authorization;
use OAuth2;
use OAuth2\Storage;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use ChadicusTest\Slim\OAuth2\Middleware\Support\CallableMiddleware;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Middleware\Authorization class.
 *
 * @coversDefaultClass \Chadicus\Slim\OAuth2\Middleware\Authorization
 * @covers ::<private>
 * @covers ::__construct
 */
final class AuthorizationTest extends TestCase
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

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => null,
        ];
        $test = $this;
        $next = new CallableMiddleware(function ($request) use ($expectedToken, $test) {
            $test->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return new Response();
        });

        $middleware->process($request, $next);

        $this->assertSame($expectedToken, $container['token']);
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

        $next = new CallableMiddleware(function ($request) {
            throw new \Exception('this will not get executed');
        });

        $response = $middleware->process($request, $next);

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

        $container = new ArrayObject();

        $middleware = new Authorization($server, $container);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => 'allowFoo anotherScope',
        ];
        $test = $this;
        $next = new CallableMiddleware(function ($request) use ($expectedToken, $test) {
            $test->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return new Response();
        });

        $response = $middleware->withRequiredScope(['allowFoo'])->process($request, $next);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($expectedToken , $container['token']);
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

        $next = new CallableMiddleware(function ($request) {
            throw new \Exception('this will not get executed');
        });

        $response = $middleware->process($request, $next);

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

        $next = new CallableMiddleware(function ($request) {
            throw new \Exception('this will not get executed');
        });

        $response = $middleware->process($request, $next);

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

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => 'basicUser withPermission anExtraScope',
        ];
        $test = $this;
        $next = new CallableMiddleware(function ($request) use ($expectedToken, $test) {
            $test->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return new Response();
        });

        $response = $middleware->process($request, $next);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($expectedToken, $container['token']);
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

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => null,
        ];
        $test = $this;
        $next = new CallableMiddleware(function ($request) use ($expectedToken, $test) {
            $test->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return new Response();
        });

        $middleware->process($request, $next);

        $this->assertSame($expectedToken , $container['token']);
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

        $middleware = new Authorization($server, new ArrayObject());

        $next = new CallableMiddleware(function ($request) {
            throw new \Exception('this will not get executed');
        });

        $response = $middleware->process($request, $next);

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

        $middleware = new Authorization($oauth2ServerMock, new ArrayObject());
        $next = new CallableMiddleware(function ($request) {
            throw new \Exception('this will not get executed');
        });

        $response = $middleware->process(new ServerRequest(), $next);
        $this->assertSame('text/html', $response->getHeaderLine('Content-Type'));
    }

    /**
     * Ensure $container must be an instance of ArrayAccess or ContainerInterface.
     *
     * @test
     * @covers ::__construct
     *
     * @return void
     */
    public function constructWithInvalidContainer()
    {

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('$container does not implement ArrayAccess or contain a \'set\' method');

        $oauth2ServerMock = $this->getMockBuilder('\\OAuth2\\Server')->disableOriginalConstructor()->getMock();
        new Authorization($oauth2ServerMock, new \StdClass());
    }

    /**
     * Verify middleware cannot be constructed with a pure PSR-11 container.
     *
     * @test
     * @covers ::__construct
     *
     * @return void
     */
    public function constructWithPSR11Container()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('$container does not implement ArrayAccess or contain a \'set\' method');

        $container = $this->getMockBuilder('\\Psr\\Container\\ContainerInterface')->getMock();
        $oauth2ServerMock = $this->getMockBuilder('\\OAuth2\\Server')->disableOriginalConstructor()->getMock();
        new Authorization($oauth2ServerMock, $container);
    }

    /**
     * Verify middleware can use interop container.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invokeWithInteropContainer()
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

        $container = (new \DI\ContainerBuilder())->build();

        $middleware = new Authorization($server, $container);

        $expectedToken = [
            'access_token' => 'atokenvalue',
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => 99999999900,
            'scope' => null,
        ];
        $test = $this;
        $next = new CallableMiddleware(function ($request) use ($expectedToken, $test) {
            $test->assertSame($expectedToken, $request->getAttribute(Authorization::TOKEN_ATTRIBUTE_KEY));
            return new Response();
        });

        $middleware->process($request, $next);

        $this->assertSame($expectedToken, $container->get('token'));
    }
}
