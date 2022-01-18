<?php

namespace ChadicusTest\Slim\OAuth2\Middleware\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CallableMiddleware implements RequestHandlerInterface
{
    private $handler;

    public function __construct(callable $handler)
    {
        $this->handler = $handler;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return call_user_func($this->handler, $request);
    }
}
