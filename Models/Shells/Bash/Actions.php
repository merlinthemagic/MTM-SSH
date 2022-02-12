<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH\Models\Shells\Bash;

class Actions extends \MTM\Shells\Models\Shells\Bash\Actions
{
	public function scpFolderByPassword($srcDir, $dstDir, $ip, $userName, $password, $port=22, $timeout=30000)
	{
		if (is_object($srcDir) === false) {
			$srcDir	= \MTM\FS\Factories::getDirectories()->getDirectory($srcDir);
		}
		if (is_object($dstDir) === false) {
			$dstDir	= \MTM\FS\Factories::getDirectories()->getDirectory($dstDir);
		}
		if (is_object($ip) === false) {
			$ip		= \MTM\Network\Factories::getIp()->getIpFromString($ip);
		}
		$scpTool	= \MTM\SSH\Factories::getFiles()->getScpTool();
		return $scpTool->passwordCopy($this, $srcDir, $dstDir, $ip, $userName, $password, $port, $timeout);
	}
}