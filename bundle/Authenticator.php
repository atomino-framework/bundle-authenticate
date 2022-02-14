<?php namespace Atomino\Bundle\Authenticate;

use JetBrains\PhpStorm\Pure;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint;

class Authenticator {

	const TOKEN_AUTH = 'AUTH';
	const TOKEN_REFRESH = 'REFRESH';
	protected const CHECKSUM = 'cks';
	protected const STRONG_EXPIRES_AT = 'str';

	protected AuthenticableInterface|null $authenticated = null;
	private int|null $strongExpiresAt = null;

	public function __construct(private Configuration $jwtConfig, private string $authenticable) { }

	protected function findUser(string $login): AuthenticableInterface|null {
		/** @var \Atomino\Bundle\Authenticate\AuthenticableInterface $authenticable */
		$authenticable = $this->authenticable;
		$user = $authenticable::findUserByLogin($login);
		return $user;
	}
	protected function pickUser(int $id): AuthenticableInterface|null {
		/** @var \Atomino\Bundle\Authenticate\AuthenticableInterface $authenticable */
		$authenticable = $this->authenticable;
		/** @var \Atomino\Bundle\Authenticate\AuthenticableInterface $user */
		$user = $authenticable::pick($id);
		if(is_null($user)) return null;
		return $user->isAuthenticable() ? $user : null;
	}

	public function get(): AuthenticableInterface|null { return $this->authenticated; }
	#[Pure] public function isAuthenticated(): bool { return !is_null($this->authenticated); }
	public function isStrong(int $timeout): bool { return !is_null($this->strongExpiresAt) && ($this->strongExpiresAt > time()); }

	public function refreshAuthToken(string $tokenString, $authTimeout): string|false {
		return is_null($user = $this->parseToken($tokenString, self::TOKEN_REFRESH)) ? false : $this->createAuthToken($user, $authTimeout);
	}
	public function authenticate(string $tokenString): bool {
		/** @var \Lcobucci\JWT\Token\Plain $token */
		$user = $this->parseToken($tokenString, self::TOKEN_AUTH, $token);
		if (!is_null($user)) {
			$this->authenticated = $user;
			$this->strongExpiresAt = $token->claims()->get(static::STRONG_EXPIRES_AT);
			return true;
		}
		return false;
	}
	public function clear() {
		$this->authenticated = null;
		$this->authenticatedAt = null;
	}

	/**
	 * @param string $login
	 * @param string $password
	 * @param int $authTimeout 0 means forever
	 * @param int $strongTimeout 0 means never
	 * @return string|false token
	 */
	public function login(string $login, string $password, int $authTimeout, int $strongTimeout = 0): string|false {
		if (($user = $this->findUser($login))?->checkPassword($password) && $user->isAuthenticable()) {
			return $this->createAuthToken($user, $authTimeout, $strongTimeout);
		}
		return false;
	}
	public function createRefreshToken($timeout): string|false { return $this->authenticated ? $this->createToken($this->authenticated, self::TOKEN_REFRESH, $timeout) : false; }

	protected function createAuthToken(AuthenticableInterface $user, int $authTimeout, int $strongTimeout = 0): string {
		$claims = [];
		$claims[static::STRONG_EXPIRES_AT] = time() + $strongTimeout;
		return $this->createToken($user, self::TOKEN_AUTH, $authTimeout, $claims);
	}

	protected function createToken(AuthenticableInterface $user, string $type, int $expiration = 0, array $claims = []): string {
		$builder = $this->jwtConfig->builder();
		foreach ($claims as $claim => $value) $builder->withClaim($claim, $value);
		$builder->issuedAt(new \DateTimeImmutable());
		$builder->relatedTo($user->id);
		$builder->withClaim(static::CHECKSUM, $user->getPasswordChecksum());
		$builder->issuedBy($type);
		if ($expiration > 0) $builder->expiresAt(\DateTimeImmutable::createFromFormat('U', time() + $expiration));
		return $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey())->toString();
	}

	protected function parseToken(string $tokenString, string $type, \Lcobucci\JWT\Token\Plain &$token = null): AuthenticableInterface|null {
		/** @var \Lcobucci\JWT\Token\Plain $token */
		try {
			$token = $this->jwtConfig->parser()->parse($tokenString);
		} catch (\Exception $e) {
			return null;
		}

		if ($this->jwtConfig->validator()->validate($token, new Constraint\SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey())) === false) return null;

		/** @var \DateTime|null $expiration */
		$expiration = $token->claims()->get('exp');

		if ($token->claims()->get('iss') !== $type) return null;
		if (!is_null($expiration) && (new \DateTimeImmutable())->getTimestamp() > $expiration->getTimestamp()) return null;
		if (is_null($user = $this->pickUser(intval($token->claims()->get('sub'))))) return null;
		if ($user->getPasswordChecksum() !== $token->claims()->get(static::CHECKSUM)) return null;

		return $user;
	}
}
