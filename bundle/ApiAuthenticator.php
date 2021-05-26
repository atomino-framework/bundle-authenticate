<?php namespace Atomino\Bundle\Authenticate;

use Symfony\Component\HttpFoundation\Request;

class ApiAuthenticator {

	protected const AUTH_HEADER = 'Authorization';
	protected const AUTH_PREFIX = 'Bearer ';

	public function __construct(private Authenticator $authenticator, private Request $request, protected int $timeoutAuth = 60 * 60 * 10, protected int $timeoutStrong = 60 * 10, protected int $timeoutRefresh = 30 * 24 * 60 * 60) { }

	public function state() {
		!is_null($authToken = $this->parseHeader()) && $this->authenticator->authenticate($authToken);
	}

	protected function parseHeader(): string|null {
		$header = $this->request->headers->get(static::AUTH_HEADER);
		if (!is_null($header) && str_starts_with($header, static::AUTH_PREFIX)) return substr($header, strlen(static::AUTH_PREFIX));
		return null;
	}

	public function authenticate(string $authToken): bool { return $this->authenticator->authenticate($authToken); }

	public function login(string $login, string $password): string|false {
		return (
			($authToken = $this->authenticator->login($login, $password, $this->timeoutAuth, $this->timeoutStrong)) &&
			$this->authenticator->authenticate($authToken)
		) ? $authToken : false;
	}

	public function getAuthToken(string $refreshToken): string|false {
		return ($authToken = $this->authenticator->refreshAuthToken($refreshToken, $this->timeoutAuth)) ? $authToken : false;
	}

	public function getRefreshToken(): string|false {
		return ($this->authenticator->isAuthenticated() && ($refreshToken = $this->authenticator->createRefreshToken($this->timeoutRefresh))) ? $refreshToken : false;
	}

}