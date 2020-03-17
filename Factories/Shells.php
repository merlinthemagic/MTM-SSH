<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Factories;

class Shells extends Base
{
	public function passwordAuthentication($ip, $user, $pass, $ctrlObj=null, $port=22, $timeout=30000)
	{
		//generic password authentication
		if (is_object($ip) === false) {
			$ip		= \MTM\Network\Factories::getIp()->getIpFromString($ip);
		}
		if (is_object($ctrlObj) === false) {
			$ctrlObj	= $this->getBaseShell();
		}
		return $this->getTool($ctrlObj)->passwordAuthenticate($ctrlObj, $ip, $user, $pass, $port, $timeout);
	}
	public function keyAuthentication($ip, $user, $key, $ctrlObj=null, $port=22, $timeout=30000)
	{
		//generic public key authentication
		if (is_object($ip) === false) {
			$ip		= \MTM\Network\Factories::getIp()->getIpFromString($ip);
		}
		if (is_object($key) === false) {
			$key	= \MTM\Encrypt\Factories::getRSA()->getPrivateKey($key);
		}
		if (is_object($ctrlObj) === false) {
			$ctrlObj	= $this->getBaseShell();
		}
		return $this->getTool($ctrlObj)->publicKeyAuthenticate($ctrlObj, $ip, $user, $key, $port, $timeout);
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
			return \MTM\Shells\Factories::getShells()->getBash();
		} else {
			throw new \Exception("Not handled");
		}
	}
}