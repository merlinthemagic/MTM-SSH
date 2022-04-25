<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\Bash;

class Actions extends Destination
{
	public function passwordAuthenticate($ctrlObj, $ipObj, $userName, $password, $port=22, $timeout=30000)
	{
		return $this->passwordConnect($ctrlObj, $ipObj, $userName, $password, $port, $timeout);
	}
	public function publicKeyAuthenticate($ctrlObj, $ipObj, $userName, $keyObj, $port=22, $timeout=30000)
	{
		return $this->keyConnect($ctrlObj, $ipObj, $userName, $keyObj, $port, $timeout);
	}
}