<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\Bash;

abstract class PasswordAuthentication extends PublicKeyAuthentication
{
	protected function passwordConnect($ctrlObj, $ipObj, $userName, $password, $port=22, $timeout=30000)
	{
		if ($ctrlObj->getType() == "bash") {
			return $this->passwordConnectFromBash($ctrlObj, $ipObj, $userName, $password, $port, $timeout);
		} else {
			throw new \Exception("Not handled");
		}
	}
	protected function passwordConnectFromBash($ctrlObj, $ipObj, $userName, $password, $port=22, $timeout=30000)
	{
		//NOTES:
		//the -T option is needed to correct an issue when connecting to Windows OPENSSH
		//but we cannot set it or connections to linux/routeros etc have issues
		//https://github.com/PowerShell/Win32-OpenSSH/issues/712
		
		$strCmd	= "ssh";
		$strCmd	.= " -p " . $port;
		$strCmd	.= " -o \"NumberOfPasswordPrompts 1\"";
		$strCmd	.= " -o \"ConnectTimeout " .ceil($timeout / 1000). "\"";
		$strCmd	.= " -o \"ServerAliveInterval 60\"";
		$strCmd	.= " -o \"ServerAliveCountMax 2628000\"";
		
		//the known_hosts file cannot be created by the webserver, so we use /dev/null
		//src: http://linuxcommand.org/man_pages/ssh1.html search for "-o option"
		//openSSH has hardcoded the use of the user home dir as the location for the .ssh dir;
		//if the command complains about not being able to write to the dir
		//you can execute this command as a user able to write to the webserver user home dir:
		//$strCmd	= "webHome=\$( getent passwd \"\$(whoami)\" | cut -d: -f6 ); sshHome=\"\$webHome/.ssh\"; mkdir -p \$sshHome; ln -s \$sshHome /dev/null";
		$strCmd	.= " -o UserKnownHostsFile=\"/dev/null\"";
		$strCmd	.= " -o \"StrictHostKeyChecking no\"";
		$strCmd	.= " -o \"GSSAPIAuthentication no\"";
		$strCmd	.= " ".$userName."@".$ipObj->getAsString("std", false);
		
		$regExs	= array(
				$ipObj->getAsString("std", false) . "'s password:"	=> "pwAuth",
				"Microsoft Corporation"								=> "windows",
				"Do you want to see the software license"			=> "routeros",
				"Use command at the base level"						=> "routeros",
				"No route to host"									=> "error",
				"Could not resolve hostname"						=> "error",
				"Connection reset by peer"							=> "error",
				"Connection timed out"								=> "error",
				"Permission denied"									=> "error",
				"Connection closed by remote host"					=> "error",
				"Connection refused"								=> "error",
		);
		$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
		try {
			
			$pad	= 5000; //we want the connect error
			$cmdObj	= $ctrlObj->getCmd($strCmd, $regEx, ($timeout + $pad));
			$data	= $cmdObj->get();
		
		} catch (\Exception $e) {
			//can always peak in $cmdObj->getData() to see what was returned
			//this connect is special because bash forms the base for most connects
			throw $e;
		}

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
			//login, add more regex options
			//cannot include this one above as it will match before the pwAuth
			$regExs[$userName . "@"]	= "linux";
			
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
			
			return $this->getDestinationShell($ctrlObj, $userName);
			
		} elseif ($rType == "routeros") {
			
			if ($rValue == "Do you want to see the software license") {
				//we are the only ones with the information needed to clear the prompt
				//if we dont clear it here the Destination function will have a hell of a time figuring out whats going on
				$strCmd	= "n";
				$regEx	= "(" . implode("|", array_keys($regExs)) . ")";
				$ctrlObj->getCmd($strCmd, $regEx, $timeout)->get();
			}

			return \MTM\SSH\Factories::getShells()->getRouterOsTool()->getDestinationShell($ctrlObj, $userName);
			
		} elseif ($rType == "error") {
			throw new \Exception("Connect error: " . $rValue);
		} else {
			throw new \Exception("Not Handled: " . $rType);
		}
	}
}