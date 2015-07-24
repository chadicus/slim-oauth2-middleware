<?php
namespace Chadicus\Slim\OAuth2\Middleware;

use OAuth2;
use Chadicus\Slim\OAuth2\Http\MessageBridge;

class Authorization extends \Slim\Middleware
{
    /**
     * OAuth2 Server
     *
     * @var OAuth2\Server
     */
    private $server;

    /**
     * Create a new instance of the Authroization middleware
     *
     * @param OAuth2\Server $server The configured OAuth2 server.
     */
    public function __construct(OAuth2\Server $server)
    {
        $this->server = $server;
    }

    /**
     * Verify request contains valid access token.
     *
     * @return void
     */
    public function call()
    {
        if (!$this->server->verifyResourceRequest(MessageBridge::newOauth2Request($this->app->request()))) {
            MessageBridge::mapResponse($this->server->getResponse(), $this->app->response());
            return;
        }

        $this->app->token = $this->server->getResourceController()->getToken();

        if ($this->next !== null) {
            $this->next->call();
        }
    }

    /**
     * Allows this middleware to be used as a callable.
     *
     * @return void
     */
    public function __invoke()
    {
        $this->call();
    }
}
