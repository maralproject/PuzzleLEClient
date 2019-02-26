<?php
namespace LE;

use LEClient\LEOrder;

/* Make sure that the server uses PHP 7 */
if(!version_compare(PHP_VERSION,"7.1.0",">=")){
	throw new PuzzleError("PuzzleLE Client require PHP7.1!");
}

require("vendor/LEClient/LEClient.php");
require("vendor/cloudflare/autoload.php");

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

class ACME{
	public static function recursiveRemoveDirectory($directory)
	{
		foreach(glob("{$directory}/*") as $file){
			if(is_dir($file)) self::recursiveRemoveDirectory($file);
			else unlink($file);
		}
		rmdir($directory);
	}

	/**
	 * Get new ACME instance
	 * @param bool $use_staging
	 * @param integer $log_level
	 * @return \LEClient
	 */
	public static function getInstance($common_name = "", $use_staging = true, $log_level = NULL){
		$common_name = trim($common_name);
		$le_email = \LE\Config::get("email");
		$wd = rtrim(str_replace("\\","/",\LE\Config::get("dir")),"/");
		
		if(!filter_var($le_email,FILTER_VALIDATE_EMAIL)) 
			throw new \PuzzleError("Please set the correct email address using\n\tphp puzzleos letsencrypt set --email you@example.com");
		if($common_name == "")
			throw new \PuzzleError("Common name cannot be empty!");
		if(strlen($common_name) > 50)
			throw new \PuzzleError("Common name must be less than 50 characters long!");
		if(!file_exists($wd))
			throw new \PuzzleError("Directory not found: $wd\nPlease set the correct path for working directory using\n\t'php puzzleos letsencrypt set --dir \"/var/html/cert\"");
		else{
			@mkdir("$wd/$common_name");
			$wd .= "/$common_name";
		}
		
		/**
		 * Known bugs:
		 * Sometimes, OPENSSL_CONF path not set up already in windows, which
		 * confuses openssl to generate RSA keys.
		 * 
		 * On windows
		 * 1. Go to SYSTEM
		 * 2. Click on ADVANCED SYSTEM SETTINGS
		 * 3. Click on ENVIRONMENT VARIABLES
		 * 4. Under "System Variables" click on "NEW"
		 * 5. Enter the "Variable name" OPENSSL_CONF
		 * 6. Enter the "Variable value". My is - C:\xampp\apache\conf\openssl.cnf
		 * 7. Click "OK" and close all the windows and RESTART your computer.
		 */ 
		$client = new LEClient(
			$le_email,
			$use_staging ? true : false, 
			$log_level === NULL ? LEClient::LOG_OFF : $log_level,
			$wd
		);
		
		return $client;
	}
	
	/**
	 * 
	 * @param \LEClient $client 
	 * @param string $common_name 
	 * @param array $domains 
	 * @param \PObject $io 
	 * @param bool $verbose 
	 * @return bool
	 */
	public static function revoke(LEClient $client, $common_name, $domains, $io, $verbose = true){
		if(count($domains) == 0 || !is_array($domains)) throw new \PuzzleError("Domains cannot be empty!");
		if($common_name == "") throw new \PuzzleError("Please specify common name using");
		
		foreach($domains as $dk=>$dv){
			$domains[$dk] = trim($dv);
		}
		
		$order = $client->getOrCreateOrder($common_name,$domains);
		if($verbose) $io->out("Order Created...\n");
		
		if($order->revokeCertificate()){
			//Removing autorenewal
			\Database::delete("app_letsencrypt_cert","cn",$common_name);
			if($verbose) $io->out("OK!\n");
			return true;
		}
		
		return false;
	}

	/**
	 * 
	 * @param \LEClient $client 
	 * @param string $common_name 
	 * @param array $domains 
	 * @param \PObject $io 
	 * @param bool $verbose 
	 * @return bool 
	 */
	public static function order(\LEClient $client, $common_name, $domains, $io, $autorenew = true, $verbose = false){
		if(count($domains) == 0 || !is_array($domains)) throw new \PuzzleError("Domains cannot be empty!");
		if($common_name == "") throw new \PuzzleError("Please specify common name using");
		
		foreach($domains as $dk=>$dv){
			$domains[$dk] = trim($dv);
		}
		
		CF::init();
		CF::chZone($common_name);
		
		if($verbose) $io->out("[OK] Cloudflare Connection...\n");
		
		$order = $client->getOrCreateOrder($common_name,$domains);
		if($verbose) $io->out("[OK] Order Created...\n");
		
		if(!$order->allAuthorizationsValid()){
			$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
			if($pending !== false){
				if($verbose) {
					print_r($pending);
					$io->out(count($pending)." authorization needed...\n");
				}
				foreach($pending as $k=>$d){
					$subdomain = ltrim(rtrim("_acme-challenge." . str_replace($common_name,"",$d["identifier"]),"."),".");
					
					if($verbose) $io->out("Validating $subdomain with key {$d["DNSDigest"]} #$k...\n");
					
					if(CF::add($d["DNSDigest"], $d["identifier"]) === false) throw new \PuzzleError("Cannot add DNS TXT record");
					
					for ($i=125 ; $i>0 ; $i--){
						$p_check = dns_get_record("_acme-challenge." . $d["identifier"],DNS_TXT)[0]["txt"];
						if($p_check == $d["DNSDigest"] && $i<100){
							sleep(2);
							break;
						}
						if($verbose) echo "Delaying $i secs, waiting for DNS cache to flush...\r";
						sleep(1);
					}
					$io->out("[OK] Delaying 0 secs, waiting for DNS cache to flush...\r\n");
					
					if($verbose) $io->out("Validating now #$k...\n");
					
					$ver_challenges = $order->verifyPendingOrderAuthorization($d["identifier"], LEOrder::CHALLENGE_TYPE_DNS, false);
					if($ver_challenges !== true){
						throw new \PuzzleError("Failed to verify ACME Challenge on {$d["identifier"]} with key {$d["DNSDigest"]}");
					}
					
					if($verbose) $io->out("[OK] Validated #$k...\n");
					if($verbose) $io->out("Deleting record #$k...\n");
					CF::rm($d["identifier"]);
				}
			}
		}
		
		if($order->allAuthorizationsValid()){
			if($verbose) $io->out("Getting certificate...\n");
			if(!$order->isFinalized()) $order->finalizeOrder();
			if($order->isFinalized()) $order->getCertificate();
			@\Database::delete("app_letsencrypt_cert","cn",$common_name);
			if($autorenew){
				//Renew every 60 days
				\Database::insert("app_letsencrypt_cert", [
					(new \DatabaseRowInput)
						->setField("cn", $common_name)
						->setField("domains", join(",",$domains))
						->setField("lastIssued", time())
						->setField("nextIssue", (time() + (60 * T_DAY)))
						->setField("live", $client->staging ? 0 : 1)
				]);
				if($verbose) $io->out("Certificate will be reissued after 90 days. Make sure cronjob is set properly.\n");
			}
			if($verbose) $io->out("OK!\n");
			return true;
		}else{
			if($verbose) $io->out("Some authorization missing...\n");
			$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
			if($verbose) print_r($pending);
		}
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