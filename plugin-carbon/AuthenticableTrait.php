<?php namespace Atomino\Carbon\Plugins\Authenticate;

use Atomino\Bundle\Authenticate\Authenticator;
use Atomino\Carbon\Database\Finder\Filter;

/**
 * @method static \Atomino\Carbon\Model model();
 */
trait AuthenticableTrait {

	public function setPassword(string $value) {
		$plugin = Authenticable::fetch(static::model());
		$this->{$plugin->password} = password_hash($value, PASSWORD_BCRYPT);
	}
	public function checkPassword(string $password): bool {
		$plugin = Authenticable::fetch(static::model());
		return password_verify($password, $this->{$plugin->password});
	}
	public function getPasswordChecksum(): string {
		$plugin = Authenticable::fetch(static::model());
		return md5($this->{$plugin->password});
	}
	public static function isAuthenticated(): bool { return static::model()->getContainer()->get(Authenticator::class)->isAuthenticated(); }
	public static function getAuthenticated(): static|null { return static::model()->getContainer()->get(Authenticator::class)->get(); }
	public function isAuthenticable(): bool { return true; }
	public static function findUserByLogin(string $login): static|null {
		$plugin = Authenticable::fetch(static::model());
		return static::search(Filter::where($plugin->login . ' = $1', $login))->pick();
	}

}