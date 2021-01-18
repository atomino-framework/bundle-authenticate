<?php namespace Atomino\Molecules\Middleware\Auth;

use Atomino\Molecules\Module\Authenticator\SessionAuthenticator;
use Atomino\Responder\Middleware;
use Symfony\Component\HttpFoundation\Response;

class SessionAuth extends Middleware{

	public function __construct(private SessionAuthenticator $authenticator){ }

	protected function respond(Response $response): Response{
		$this->next($response);
		$this->authenticator->redeployRefreshToken($response);
		return $response;
	}
}