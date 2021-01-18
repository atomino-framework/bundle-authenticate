<?php namespace Atomino\Molecules\Module\Authenticator;

use Atomino\Core\Application;
use Atomino\Molecules\EntityPlugin\Authenticable\Authenticable;

/**
 * @property-read int $id
 */
interface AuthenticableInterface{
	public function checkPassword(string $password): bool;
	public function getPasswordChecksum(): string;
	public function setPassword(string $value);
	public function isAuthenticable():bool;
	public static function isAuthenticated():bool;
	public static function getAuthenticated():static|null;
	public static function findUserByLogin(string $login): static|null;
}