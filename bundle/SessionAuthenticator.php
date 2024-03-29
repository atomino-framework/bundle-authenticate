<?php namespace Atomino\Bundle\Authenticate;

use DI\Container;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use function Atomino\debug;

class SessionAuthenticator {

	protected const AUTH_TOKEN_SESSION = 'authToken';
	protected const REFRESH_TOKEN_COOKIE = 'authToken';

	private \Symfony\Component\HttpFoundation\Session\SessionInterface $session;
	private \Symfony\Component\HttpFoundation\InputBag $cookies;

	public function __construct(
		private Authenticator $authenticator,
		private Request       $request,
		private Container     $container,
		protected int         $timeoutAuth = 0,
		protected int         $timeoutStrong = 60 * 5,
		protected int         $timeoutRefresh = 30 * 24 * 60 * 60
	) {
		if (!$this->request->hasSession()) $this->request->setSession($container->get(SessionInterface::class));
		$this->session = $this->request->getSession();
		$this->cookies = $this->request->cookies;

		$authToken = $this->session->get(static::AUTH_TOKEN_SESSION);
		if (!is_null($authToken)) {
			if ($this->authenticator->authenticate($authToken)) return;
			$this->session->remove(static::AUTH_TOKEN_SESSION);
		}
		$refreshToken = $this->cookies->get(static::REFRESH_TOKEN_COOKIE);
		if (!is_null($refreshToken)) {
			if (
				($authToken = $this->authenticator->refreshAuthToken($refreshToken, $this->timeoutAuth)) &&
				$this->authenticator->authenticate($authToken)
			) $this->session->set(static::AUTH_TOKEN_SESSION, $authToken);
		}
	}

	public function getAuthenticator(): Authenticator { return $this->authenticator; }

	public function login(string $login, string $password): bool {
		$authToken = $this->authenticator->login($login, $password, $this->timeoutAuth, $this->timeoutStrong);

		if ($authToken && $this->authenticator->authenticate($authToken)) {
			$this->deployAuthToken($authToken);
		}
		return $this->authenticator->isAuthenticated();
	}

	public function deployAuthToken($authToken) {
		$this->session->set(static::AUTH_TOKEN_SESSION, $authToken); }

	public function redeployRefreshToken(Response $response) {
		if ($this->authenticator->isAuthenticated() && $this->cookies->has(static::REFRESH_TOKEN_COOKIE)) {
			$this->deployRefreshToken($response);
		}
	}

	public function deployRefreshToken(Response $response) {
		if ($this->authenticator->isAuthenticated() && $refreshToken = $this->authenticator->createRefreshToken($this->timeoutRefresh)) {
			$response->headers->setCookie(new Cookie(self::REFRESH_TOKEN_COOKIE, $refreshToken, strtotime('now + ' . $this->timeoutRefresh . 'seconds')));
		} else $response->headers->clearCookie(static::REFRESH_TOKEN_COOKIE);
	}

	public function logout(Response $response) {
		$this->authenticator->clear();
		$this->session->remove(static::AUTH_TOKEN_SESSION);
		$response->headers->clearCookie(static::REFRESH_TOKEN_COOKIE);
	}

}