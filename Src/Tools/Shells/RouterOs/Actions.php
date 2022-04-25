<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Tools\Shells\RouterOs;

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
	public function getFormattedUsername($userName)
	{
		//default terminal options for all Mikrotik SSH connections.
		//We need the terminal without colors and a standard width / height
		$rosOpts	= "ct1000w1000h";
		if (strpos($userName, "+") !== false) {
			if (preg_match("/(.*?)\+(.*)/", $userName, $raw) == 1) {
				//username has options, but they may be the wrong ones
				$userName	= $raw[1] . "+" . $rosOpts;
			} else {
				throw new \Exception("Not handled");
			}
		} else {
			$userName	.= "+" . $rosOpts;
		}
		return $userName;
	}
}