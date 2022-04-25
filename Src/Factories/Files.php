<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Factories;

class Files extends Base
{
	public function getScpTool()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]		= new \MTM\SSH\Tools\Files\SCP\Zstance();
		}
		return $this->_s[__FUNCTION__];
	}
}