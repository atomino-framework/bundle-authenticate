<?php namespace Atomino\Mercury\Plugins\Authenticate;

use Atomino\Bundle\Authenticate\SessionAuthenticator;
use Atomino\Mercury\Pipeline\Handler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class SessionAuth extends Handler {

	public function __construct(private SessionAuthenticator $authenticator) { }

	public function handle(Request $request): Response {
		$response = $this->next($request);
		$this->authenticator->redeployRefreshToken($response);
		return $response;
	}
}