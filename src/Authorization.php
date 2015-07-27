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
     * @param array $scope Scopes required for authorization
     *
     * @return void
     */
    public function call(array $scope = null)
    {
        $scope = empty($scope) ? null : implode(' ', $scope);
        if (!$this->server->verifyResourceRequest(MessageBridge::newOauth2Request($this->app->request()), null, $scope)) {
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

    /**
     * Returns a callable function to be used as a authorization middleware with a specified scope.
     *
     * @param array $scope Scopes require for authorization
     *
     * @return void
     */
    public function withRequiredScope(array $scope)
    {
        $auth = $this;
        return function () use ($auth, $scope) {
            return $auth->call($scope);
        };
    }
}
