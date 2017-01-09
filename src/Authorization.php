<?php
namespace Chadicus\Slim\OAuth2\Middleware;

use ArrayAccess;
use Chadicus\Slim\OAuth2\Http\RequestBridge;
use Chadicus\Slim\OAuth2\Http\ResponseBridge;
use Chadicus\Psr\Middleware\MiddlewareInterface;
use DI;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use OAuth2;

/**
 * Slim Middleware to handle OAuth2 Authorization.
 */
class Authorization implements MiddlewareInterface
{
    /**
     * OAuth2 Server
     *
     * @var OAuth2\Server
     */
    private $server;

    /**
     * Array of scopes required for authorization.
     *
     * @var array
     */
    private $scopes;

    /**
     * Container for token.
     *
     * @var ArrayAccess
     */
    private $container;

    /**
     * Create a new instance of the Authorization middleware.
     *
     * @param OAuth2\Server $server    The configured OAuth2 server.
     * @param DI\Container  $container A container object in which to store the token from the request.
     * @param array         $scopes    Scopes required for authorization. $scopes can be given as an array of arrays. OR
     *                                 logic will use with each grouping.  Example:
     *                                 Given ['superUser', ['basicUser', 'aPermission']], the request will be verified
     *                                 if the request token has 'superUser' scope OR 'basicUser' and 'aPermission' as
     *                                 its scope.
     */
    public function __construct(OAuth2\Server $server, DI\Container $container, array $scopes = [])
    {
        $this->server = $server;
        $this->container = $container;
        $this->scopes = $this->formatScopes($scopes);
    }

    /**
     * Execute this middleware.
     *
     * @param  ServerRequestInterface $request  The PSR7 request.
     * @param  ResponseInterface      $response The PSR7 response.
     * @param  callable               $next     The Next middleware.
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        $oauth2Request = RequestBridge::toOAuth2($request);
        foreach ($this->scopes as $scope) {
            if ($this->server->verifyResourceRequest($oauth2Request, null, $scope)) {
                $this->container->set('token', $this->server->getResourceController()->getToken());
                return $next($request, $response);
            }
        }

        $response = ResponseBridge::fromOAuth2($this->server->getResponse());

        if ($response->hasHeader('Content-Type')) {
            return $response;
        }

        return $response->withHeader('Content-Type', 'application/json');
    }

    /**
     * Returns a callable function to be used as a authorization middleware with a specified scope.
     *
     * @param array $scopes Scopes require for authorization.
     *
     * @return Authorization
     */
    public function withRequiredScope(array $scopes)
    {
        $clone = clone $this;
        $clone->scopes = $clone->formatScopes($scopes);
        return $clone;
    }

    /**
     * Helper method to ensure given scopes are formatted properly.
     *
     * @param array $scopes Scopes required for authorization.
     *
     * @return array The formatted scopes array.
     */
    private function formatScopes(array $scopes)
    {
        if (empty($scopes)) {
            return [null]; //use at least 1 null scope
        }

        array_walk(
            $scopes,
            function (&$scope) {
                if (is_array($scope)) {
                    $scope = implode(' ', $scope);
                }
            }
        );

        return $scopes;
    }
}
