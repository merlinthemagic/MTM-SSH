<?php
//� 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\RouterOs;

class Destination extends PasswordAuthentication
{
	public function getDestinationShell($ctrlObj, $userName) 
	{
		if ($this->getFormattedUsername($userName) != $userName) {
			//usernames must be formatted correctly when connecting to RouterOs
			//we cannot know wht we are connecting to ahead of time, so its up to you
			//to pass the username through the following function before connecting to routerOS
			//use: \MTM\SSH\Factories::getShells()->getRouterOsTool()->getFormattedUsername($userName);
			throw new \Exception("Username is invalid for RouterOs");
		}
		$childObj	= \MTM\SSH\Factories::getShells()->getRouterOs();
		$childObj->setParent($ctrlObj);
		$ctrlObj->setChild($childObj);
		//init the shell, we are already logged in
		$childObj->initialize();
		return $childObj;
	}
}