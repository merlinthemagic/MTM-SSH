<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\Bash;

class Destination extends PasswordAuthentication
{
	public function getDestinationShell($ctrlObj, $userName)
	{
		//figure out what type of shell we got on the other side
		$strCmd	= "ps hp $$ | awk '{print $5}'";
		$regEx	= "(@)";
		$data	= $ctrlObj->getCmd($strCmd, $regEx)->get();

		$regExs	= array(
				"-bash"		=> "bash"
		);

		$rType	= null;
		foreach ($regExs as $regEx => $type) {
			if (preg_match("/".$regEx."/", $data) == 1) {
				$rType	= $type;
				break;
			}
		}

		if ($rType == "bash") {
			$childObj	= \MTM\SSH\Factories::getShells()->getBash();
			$childObj->setParent($ctrlObj);
			$ctrlObj->setChild($childObj);
			//init the shell, we are already logged in
			$childObj->getCmd("whoami")->get();
			return $childObj;
			
		} else {
			throw new \Exception("Not Handled");
		}
	}
}