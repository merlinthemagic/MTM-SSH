<?php
//� 2019 Martin Peter Madsen
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
		
		$rawUser	= $userName;
		if (preg_match("/(.+?)\+ct1000w1000h$/", $userName, $raw) === 1) {
			//mikrotik formatted username
			$rawUser	= $raw[1];
		}
		
		$regExs	= array(
				"password:"											=> "pwAuth",
				"Microsoft Corporation"								=> "windows",
				"\[".$rawUser."\@(.+?)\] \>"						=> "routeros",
				"Do you want to see the software license\?"			=> "routeros",
				"remove it, you will be disconnected\."				=> "routeros",
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
			if ($rValue == "remove it, you will be disconnected\.") {
				//we are the only ones with the information needed to clear the prompt of the question regarding default config
				//if we dont clear it here the Destination function will have a hell of a time figuring out whats going on
				$strCmd	= "n";
				$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
				$cmdObj		= $ctrlObj->getCmd($strCmd, $regEx, $timeout);
				$cmdObj->get();
				$data		= $cmdObj->getReturnData(); //need return data so the prompt is not stripped out
				
				$rType	= null;
				foreach ($regExs as $regEx => $type) {
					if (preg_match("/".$regEx."/", $data) == 1) {
						$rValue	= $regEx;
						$rType	= $type;
						break;
					}
				}
			}
			if ($rValue == "Do you want to see the software license\?") {
				//we are the only ones with the information needed to clear the prompt
				//if we dont clear it here the Destination function will have a hell of a time figuring out whats going on
				$strCmd	= "n";
				$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
				$cmdObj		= $ctrlObj->getCmd($strCmd, $regEx, $timeout);
				$cmdObj->get();
				$data		= $cmdObj->getReturnData(); //need return data so the prompt is not stripped out
				
				$rType	= null;
				foreach ($regExs as $regEx => $type) {
					if (preg_match("/".$regEx."/", $data) == 1) {
						$rValue	= $regEx;
						$rType	= $type;
						break;
					}
				}
			}
			//there can be both a license and a forced password change one after the other
			if ($rValue == "new password\>") {
				//MT forcing password change, deny the change
				$strCmd		= chr(3);
				$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
				$ctrlObj->getCmd($strCmd, $regEx, $timeout)->get();
			}
			
			return $this->getDestinationShell($ctrlObj, $userName);
		} 
		
		if ($rType == "error") {
			throw new \Exception("Connect error: " . $rValue);
		} else {
			throw new \Exception("Not Handled: " . $rType);
		}
	}
}