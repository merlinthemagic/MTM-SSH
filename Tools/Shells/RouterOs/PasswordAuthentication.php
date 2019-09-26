<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\RouterOs;

class PasswordAuthentication extends PublicKeyAuthentication
{
	protected function passwordConnect($ctrlObj, $ipObj, $userName, $password, $port=22, $timeout=30000)
	{
		if ($ctrlObj->getType() == "routeros") {
			return $this->passwordConnectFromRouterOs($ctrlObj, $ipObj, $userName, $password, $port, $timeout);
		} else {
			throw new \Exception("Not handled");
		}
	}
	protected function passwordConnectFromRouterOs($ctrlObj, $ipObj, $userName, $password, $port=22, $timeout=30000)
	{
		$strCmd	= "/system ssh";
		$strCmd	.= " port=" . $port;
		$strCmd	.= " user=\"".$userName."\"";
		$strCmd	.= " address=\"".$ipObj->getAsString("std", false) . "\"";
		
		$regExs	= array(
				"password:"											=> "pwAuth",
				"Microsoft Corporation"								=> "windows",
				"Do you want to see the software license"			=> "routeros",
				"Use command at the base level"						=> "routeros",
				"No route to host"									=> "error",
				"Connection timed out"								=> "error",
				$userName . "@"										=> "linux"
		);
		
		$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
		$data	= $ctrlObj->getCmd($strCmd, $regEx, $timeout)->get();
		
		$rValue	= null;
		$rType	= null;
		foreach ($regExs as $regEx => $type) {
			if (preg_match("/".$regEx."/", $data) == 1) {
				$rValue	= $regEx;
				$rType	= $type;
				break;
			}
		}
		if ($rType == "pwAuth") {
		
			$strCmd	= $password;
			$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
			$data	= $ctrlObj->getCmd($strCmd, $regEx, $timeout)->get();
			
			$rType	= null;
			foreach ($regExs as $regEx => $type) {
				if (preg_match("/".$regEx."/", $data) == 1) {
					$rValue	= $regEx;
					$rType	= $type;
					break;
				}
			}
		}
		if ($rType == "linux") {
			
			return \MTM\SSH\Factories::getShells()->getBashTool()->getDestinationShell($ctrlObj, $userName);
			
		} elseif ($rType == "routeros") {
			
			if ($rValue == "Do you want to see the software license") {
				//we are the only ones with the information needed to clear the prompt
				//if we dont clear it here the Destination function will have a hell of a time figuring out whats going on
				$strCmd	= "n";
				$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
				$ctrlObj->getCmd($strCmd, $regEx, $timeout)->get();
			}

			return $this->getDestinationShell($ctrlObj, $userName);
			
		} elseif ($rType == "error") {
			throw new \Exception("Connect error: " . $rValue);
		} else {
			throw new \Exception("Not Handled: " . $rType);
		}
	}
}