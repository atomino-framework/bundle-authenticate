<?php namespace Atomino\Molecules\EntityPlugin\Authenticable;

use Atomino\Entity\Generator\CodeWriter;
use Atomino\Entity\Plugin\Plugin;
use Atomino\Molecules\Module\Authenticator\AuthenticableInterface;

#[\Attribute(\Attribute::TARGET_CLASS)]
class Authenticable extends Plugin{
	public function __construct(public $login = 'login', public $password='password'){ }
	public function generate(\ReflectionClass $ENTITY, CodeWriter $codeWriter){
		$codeWriter->addInterface(AuthenticableInterface::class);
		$codeWriter->addAttribute('#[Protect("'.$this->password.'", true, false)]');
		$codeWriter->addAttribute('#[RequiredField("'.$this->login.'", \Atomino\Entity\Field\StringField::class)]');
		$codeWriter->addAttribute('#[RequiredField("'.$this->password.'", \Atomino\Entity\Field\StringField::class)]');
	}
	public function getTrait():string|null{ return AuthenticableTrait::class;}
}