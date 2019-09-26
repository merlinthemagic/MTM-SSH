<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Docs\Examples;

class Linux
{
	protected $_ctrlObj=null;
	protected $_ipAddress="10.10.10.10";
	protected $_username="centos";
	protected $_password="secret";
	protected $_privateKey=null;
	
	public function setConfig($ip, $username, $password, $privateKey=null)
	{
		$this->_ipAddress	= $ip;
		$this->_username	= $username;
		$this->_password	= $password;
		$this->_privateKey	= $privateKey;
		return $this;
	}
	public function getVarFileList()
	{
		return $this->getConnection()->getCmd("ls -sho --color=none /var")->get();
	}
	public function pingGoogleDns()
	{
		return $this->getConnection()->getCmd("ping -c 3 8.8.8.8")->get();
	}
	public function getHostname()
	{
		return $this->getConnection()->getCmd("hostname")->get();
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