<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\Bash;

abstract class Get extends PasswordAuthentication
{
	protected function remoteVersion($ctrlObj, $ipObj, $port, $timeout)
	{
		//returns e.g. 'OpenSSH_7.4' or 'ROSSSH'
		$strCmd		= "ssh -v -p ".$port." -o UserKnownHostsFile=\"/dev/null\" -o \"StrictHostKeyChecking no\" -o \"NumberOfPasswordPrompts 0\" -o \"ConnectTimeout ".ceil($timeout / 1000)."\" abuse@dynamic-data.io@".$ipObj->getAsString("std", false);
		$rData		= trim($ctrlObj->getCmd($strCmd)->get());
		if (preg_match("/\sremote\ssoftware\sversion\s+(.+)\n/i", $rData, $raw) === 1) {
			return trim($raw[1]);
		} elseif (preg_match("/connection\srefused/i", $rData, $raw) === 1) {
			throw new \Exception("Connection refused", 13551);
		} elseif (preg_match("/no\sroute\sto\shost/i", $rData, $raw) === 1) {
			throw new \Exception("No route to host", 13552);
		} elseif (preg_match("/connection\stimed\sout/i", $rData, $raw) === 1) {
			throw new \Exception("Connection timed out", 13553);
		} else {
			throw new \Exception("Failed to determine remote software version", 13554);
		}
	}
}