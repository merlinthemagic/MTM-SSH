<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Factories;

class Shells extends Base
{
	public function passwordAuthentication($ip, $user, $pass, $ctrlObj=null, $port=22, $timeout=30000)
	{
		try {
			//generic password authentication
			if (is_object($ip) === false) {
				$ip		= \MTM\Network\Factories::getIp()->getIpFromString($ip);
			}
			if (is_object($ctrlObj) === false) {
				$newBase	= true;
				$ctrlObj	= $this->getBaseShell();
			} else {
				$newBase	= false;
			}
			return $this->getTool($ctrlObj)->passwordAuthenticate($ctrlObj, $ip, $user, $pass, $port, $timeout);
			
		} catch (\Exception $e) {
			if ($newBase === true && is_object($ctrlObj) === true) {
				$ctrlObj->terminate();
			}
			throw $e;
		}
	}
	public function keyAuthentication($ip, $user, $key, $ctrlObj=null, $port=22, $timeout=30000)
	{
		try {
			//generic public key authentication
			if (is_object($ip) === false) {
				$ip		= \MTM\Network\Factories::getIp()->getIpFromString($ip);
			}
			if (is_string($key) === true) {
				$key	= \MTM\Encrypt\Factories::getRSA()->getPrivateKey($key);
			} elseif (
				$key instanceof \MTM\Encrypt\Models\RSA\PrivateKey === false
			) {
				throw new \Exception("Not handled for key input");
			}
			if (is_object($ctrlObj) === false) {
				$newBase	= true;
				$ctrlObj	= $this->getBaseShell();
			} else {
				$newBase	= false;
			}
			return $this->getTool($ctrlObj)->publicKeyAuthenticate($ctrlObj, $ip, $user, $key, $port, $timeout);
		
		} catch (\Exception $e) {
			if ($newBase === true && is_object($ctrlObj) === true) {
				$ctrlObj->terminate();
			}
			throw $e;
		}
	}
	public function getBash()
	{
		$rObj	= new \MTM\SSH\Models\Shells\Bash\Actions();
		return $rObj;
	}
	public function getRouterOs()
	{
		$rObj	= new \MTM\SSH\Models\Shells\RouterOs\Actions();
		return $rObj;
	}
	public function getTool($ctrlObj)
	{
		if ($ctrlObj->getType() == "bash") {
			return $this->getBashTool();
		} elseif ($ctrlObj->getType() == "routeros") {
			return $this->getRouterOsTool();
		}
	}
	public function getBashTool()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]		= new \MTM\SSH\Tools\Shells\Bash\Actions();
		}
		return $this->_s[__FUNCTION__];
	}
	public function getRouterOsTool()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]		= new \MTM\SSH\Tools\Shells\RouterOs\Actions();
		}
		return $this->_s[__FUNCTION__];
	}
	protected function getBaseShell()
	{
		$osTool		= \MTM\Utilities\Factories::getSoftware()->getOsTool();
		if ($osTool->getType() == "linux") {
			$ctrlObj	= \MTM\Shells\Factories::getShells()->getBash();
			
			//trap the ssh conn exit, that way the user cannot drop into a local shell they did not create
			$strCmd		= "trap \"trap - SIGCHLD; echo mtm-forced-exit; exit\" SIGCHLD";
			$ctrlObj->getCmd($strCmd)->get();
			return $ctrlObj;
		} else {
			throw new \Exception("Not handled");
		}
	}
}