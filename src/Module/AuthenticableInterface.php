<?php namespace Atomino\Molecules\Module\Authenticator;

/**
 * @property-read int $id
 */
interface AuthenticableInterface{
	public function checkPassword($password): bool;
	public function getPasswordChecksum(): string;
}