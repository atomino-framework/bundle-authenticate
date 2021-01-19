<?php namespace Atomino\Molecules\Middleware\Auth;

use Atomino\Molecules\Module\Authenticator\ApiAuthenticator;
use Atomino\Molecules\Module\Authenticator\Authenticator;
use Atomino\Responder\Middleware;
use Symfony\Component\HttpFoundation\Response;

class AuthCheck extends Middleware{

	public static function setup(string $redirect){ parent::args(get_defined_vars()); }

	public function __construct(private Authenticator $authenticator){ }

	protected function respond(Response $response): Response{
		if($this->authenticator->isAuthenticated()) return $this->next($response);
		$response->setStatusCode(Response::HTTP_UNAUTHORIZED);
		if(!is_null($redirect = $this->getArgsBag('redirect'))) $this->redirect($response, $redirect);
		return $response;
	}
	
}