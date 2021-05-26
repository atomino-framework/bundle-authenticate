<?php namespace Atomino\Carbon\Plugins\Authenticate;

use Atomino\Bundle\Authenticate\AuthenticableInterface;
use Atomino\Carbon\Generator\CodeWriter;
use Atomino\Carbon\Plugin\Plugin;

#[\Attribute(\Attribute::TARGET_CLASS)]
class Authenticable extends Plugin {
	public function __construct(public $login = 'login', public $password = 'password') { }
	public function generate(\ReflectionClass $ENTITY, CodeWriter $codeWriter) {
		$codeWriter->addInterface(AuthenticableInterface::class);
		$codeWriter->addAttribute('#[Protect("' . $this->password . '", true, false)]');
		$codeWriter->addAttribute('#[RequiredField("' . $this->login . '", \Atomino\Carbon\Field\StringField::class)]');
		$codeWriter->addAttribute('#[RequiredField("' . $this->password . '", \Atomino\Carbon\Field\StringField::class)]');
	}
	public function getTrait(): string|null { return AuthenticableTrait::class; }
}