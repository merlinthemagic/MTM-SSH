<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Docs\Examples;

class RouterOs
{
	protected $_ctrlObj=null;
	protected $_ipAddress="10.10.10.10";
	protected $_username="admin";
	protected $_password="";
	protected $_privateKey=null;
	
	public function setConfig($ip, $username, $password, $privateKey=null)
	{
		$this->_ipAddress	= $ip;
		$this->_username	= \MTM\SSH\Factories::getShells()->getRouterOsTool()->getFormattedUsername($username);
		$this->_password	= $password;
		$this->_privateKey	= $privateKey;
		return $this;
	}
	public function getSystemResources()
	{
		return $this->getConnection()->getCmd("/system resource print")->get();
	}
	public function getInterfaces()
	{
		return $this->getConnection()->getCmd("/interface print")->get();
	}
	public function getIdentity()
	{
		return $this->getConnection()->getCmd("/system identity print")->get();
	}
	public function getConnection()
	{
		if ($this->_ctrlObj === null) {
			if ($this->_privateKey === null) {
				$this->_ctrlObj	= \MTM\SSH\Factories::getShells()->passwordAuthentication($this->_ipAddress, $this->_username, $this->_password);
			} else {
				$this->_ctrlObj	= \MTM\SSH\Factories::getShells()->keyAuthentication($this->_ipAddress, $this->_username, $this->_privateKey);
			}
		}
		return $this->_ctrlObj;
	}
}