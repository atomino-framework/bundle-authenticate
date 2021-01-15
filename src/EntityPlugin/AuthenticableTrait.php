<?php namespace Atomino\Molecules\EntityPlugin\Authenticable;

use Atomino\Core\Application;
use Atomino\Molecules\Module\Authenticator\Authenticator;

/**
 * @method static \Atomino\Entity\Model model();
 */
trait AuthenticableTrait{

	public function setPassword($value){
		$plugin = Authenticable::fetch(static::model());
		$this->{$plugin->password} = password_hash($value, PASSWORD_BCRYPT);
	}
	public function checkPassword($password): bool{
		$plugin = Authenticable::fetch(static::model());
		return password_verify($password, $this->{$plugin->password});
	}
	public function getPasswordChecksum():string{
		$plugin = Authenticable::fetch(static::model());
		return md5($this->{$plugin->password});
	}
	public static function isAuthenticated():bool{ return Application::DIC()->get(Authenticator::class)->isAuthenticated(); }
	public static function getAuthenticated():static{ return Application::DIC()->get(Authenticator::class)->get(); }

}