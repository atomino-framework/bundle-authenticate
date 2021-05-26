<?php namespace Atomino\Mercury\Plugins\Authenticate;

use Atomino\Bundle\Authenticate\ApiAuthenticator;
use Atomino\Mercury\Pipeline\Handler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ApiAuth extends Handler {

	public function __construct(private ApiAuthenticator $authenticator) { }

	public function handle(Request $request): Response|null {
		return $this->next($request);
	}

}