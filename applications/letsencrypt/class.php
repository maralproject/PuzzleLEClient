<?php
namespace LE;
defined("__POSEXEC") or die("No direct access allowed!");

require_once("vendor/LEClient/LEClient.php");
require_once("vendor/cloudflare/autoload.php");

class Config{
	public static function get($key){
		return(json_decode(\UserData::read("cnf"),true)[$key]);
	}
	
	public static function store($key,$ctn = NULL){
		$l = json_decode(\UserData::read("cnf"),true);
		if(!is_array($l)) $l = [];
		$l[$key] = $ctn;
		\UserData::store("cnf",json_encode($l),"json",true);
	}
}

class CF{
	/**
	 * @var \Cloudflare\API\Auth\APIKey
	 */
	private static $key = NULL;
	
	/**
	 * @var \Cloudflare\API\Adapter\Guzzle
	 */
	private static $adapter = NULL;
	
	/**
	 * @var \Cloudflare\API\Endpoints\User
	 */
	private static $user = NULL;
	
	/**
	 * @var \Cloudflare\API\Endpoints\Zones
	 */
	private static $zones = NULL;
	
	/**
	 * @var \Cloudflare\API\Endpoints\DNS
	 */
	private static $dns = NULL;
	private static $zoneID = NULL;
	private static $zoneName = NULL;
	
	public static function init(){
		stream_wrapper_restore("php");
		
		$cf_email = Config::get("cloudflare-email");
		$cf_key = Config::get("cloudflare-api");
		
		self::$key = new \Cloudflare\API\Auth\APIKey($cf_email, $cf_key);
		self::$adapter = new \Cloudflare\API\Adapter\Guzzle(self::$key);
		self::$user = new \Cloudflare\API\Endpoints\User(self::$adapter);
		
		if(self::$user->getUserID() == "")
			throw new PuzzleError("Cannot authenticate to cloudflare");
		
		self::$zones = new \Cloudflare\API\Endpoints\Zones(self::$adapter);
		self::$dns = new \Cloudflare\API\Endpoints\DNS(self::$adapter);
	}
	
	public static function chZone($zone){
		self::$zoneID = self::$zones->getZoneID($zone);
		self::$zoneName = $zone;
	}
	
	public static function add($challenge,$name = ""){
		$name = ltrim(rtrim("_acme-challenge." . str_replace(self::$zoneName,"",$name),"."),".");
		
		try{
			return self::$dns->addRecord(self::$zoneID, "TXT", $name, $challenge, 120, false, "");
		}catch(Exception $a){
			throw new \PuzzleError($a->getMessage());
		}
		return true;
	}
	
	public static function rm($name){
		foreach(self::$dns->listRecords(self::$zoneID)->result as $x){
			if($x->name == "_acme-challenge." . $name && $x->type == "TXT"){
				self::$dns->deleteRecord(self::$zoneID,$x->id);
			}
		}
	}
}
?>