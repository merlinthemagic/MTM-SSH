<?php
//© 2019 Martin Peter Madsen
namespace MTM\SSH;

class Factories
{
	private static $_cStore=array();
	
	//USE: $aFact		= \MTM\SSH\Factories::$METHOD_NAME();
	
	public static function getShells()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\SSH\Factories\Shells();
		}
		return self::$_cStore[__FUNCTION__];
	}
	public static function getFiles()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\SSH\Factories\Files();
		}
		return self::$_cStore[__FUNCTION__];
	}
}