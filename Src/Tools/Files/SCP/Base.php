<?php
//© 2022 Martin Peter Madsen
namespace MTM\SSH\Tools\Files\SCP;

abstract class Base extends \MTM\SSH\Tools\Files\Base
{
	public function passwordCopy($ctrlObj, $srcDir, $dstDir, $ip, $userName, $password, $port=22, $timeout=30000)
	{
		if ($ctrlObj instanceof \MTM\SSH\Models\Shells\Bash\Actions === true) {
			return $this->bashPasswordCopy($ctrlObj, $srcDir, $dstDir, $ip, $userName, $password, $port, $timeout);
		} else {
			throw new \Exception("Not handled for ctrl class");
		}
	}
	
}