<?php namespace Atomino\Molecules\EntityPlugin\Authenticable;

use Application\Entity\User;
use Atomino\Core\Application;
use Atomino\Database\Finder\Filter;
use Atomino\Molecules\Module\Authenticator\AuthenticableInterface;
use Atomino\Molecules\Module\Authenticator\Authenticator;

/**
 * @method static \Atomino\Entity\Model model();
 */
trait AuthenticableTrait{

	public function setPassword(string $value){
		$plugin = Authenticable::fetch(static::model());
		$this->{$plugin->password} = password_hash($value, PASSWORD_BCRYPT);
	}
	public function checkPassword(string $password): bool{
		$plugin = Authenticable::fetch(static::model());
		return password_verify($password, $this->{$plugin->password});
	}
	public function getPasswordChecksum():string{
		$plugin = Authenticable::fetch(static::model());
		return md5($this->{$plugin->password});
	}
	public static function isAuthenticated():bool{ return Application::DIC()->get(Authenticator::class)->isAuthenticated(); }
	public static function getAuthenticated():static|null{ return Application::DIC()->get(Authenticator::class)->get(); }
	public function isAuthenticable():bool{return true;}
	public static function findUserByLogin(string $login): static|null{
		$plugin = Authenticable::fetch(static::model());
		return static::search(Filter::where($plugin->login.' = $1', $login))->pick();
	}

}