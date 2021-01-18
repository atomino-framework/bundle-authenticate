<?php namespace Atomino\Molecules\Middleware\Auth;

use Atomino\Molecules\Module\Authenticator\ApiAuthenticator;
use Atomino\Responder\Middleware;
use Symfony\Component\HttpFoundation\Response;

class ApiAuth extends Middleware{

	public function __construct(private ApiAuthenticator $authenticator){ }

	protected function respond(Response $response): Response{
		return $this->next($response);
	}
}