<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\Bash;

class PublicKeyAuthentication extends \MTM\SSH\Tools\Shells\Base
{
	protected function keyConnect($ctrlObj, $ipObj, $userName, $keyObj, $port=22, $timeout=30000)
	{
		//we need to save the key to disk, because of this we always want the key protected
		//we do not trust the user to generate a strong enough passphrase, so we make a new one
		//if the system crashes before we can delete the key file its ok, since its encrypted
		$passPhrase		= \MTM\Utilities\Factories::getStrings()->getRandomByRegex(40, "A-Za-z0-9\#\-\+\:\;\.\,\!\*");
		$keyObj			= $keyObj->getEncryptedKey($passPhrase);
		if ($ctrlObj->getType() == "bash") {
			return $this->keyConnectFromBash($ctrlObj, $ipObj, $userName, $keyObj, $port, $timeout);
		} else {
			throw new \Exception("Not handled");
		}
	}
	protected function keyConnectFromBash($ctrlObj, $ipObj, $userName, $keyObj, $port=22, $timeout=30000)
	{
		$toSecs	= ceil($timeout / 1000);
		if ($ctrlObj->getParent() === null) {
			//on base shell use the regular file class. SSH shell factory wraps shell in SIGCHLD trap so we are only allowed to call
			//a single command or we are forced to exit. Hence we cannot place a key using the shell
			$keyFile	= \MTM\FS\Factories::getFiles()->getTempFile("pem")->setContent($keyObj->get());
			$keyFile->setMode("0600"); //keys need 600 perm before ssh will use them
			$strCmd	= "ssh";
			$strCmd	.= " -i \"".$keyFile->getPathAsString()."\"";
		} else {
			
			//place the encrypted key on the remote server
			$dirObj	= $ctrlObj->getTempDirectory();
			$strCmd	= "mtmKey=\$(mktemp --tmpdir=".$dirObj->getPathAsString().");"; //sets 600 perms by default
			$strCmd	.= " echo -n '";
			$strCmd	.= base64_encode($keyObj->get());
			$strCmd	.= "' | base64 -d > \$mtmKey;";
			//make sure we clean up after our selves
			$strCmd	.= " ( nohup sh -c 'sleep ".$toSecs."s && rm -rf \"\$0\"; ' \$mtmKey & ) > /dev/null 2>&1;"; 
			$ctrlObj->getCmd($strCmd)->get();
			
			$strCmd	= "ssh";
			$strCmd	.= " -i \$mtmKey";
		}

		$strCmd	.= " -p ".$port;
		$strCmd	.= " -o \"PreferredAuthentications publickey\"";
		$strCmd	.= " -o \"NumberOfPasswordPrompts 1\"";
		$strCmd	.= " -o \"ConnectTimeout ".$toSecs."\"";
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
				$userName."@"										=> "linux",
				"Enter passphrase for key"							=> "keyAuth",
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
		if ($rType == "keyAuth") {
			
			$strCmd	= $keyObj->getPassPhrase();
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