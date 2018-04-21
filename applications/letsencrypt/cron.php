<?php
defined("__POSEXEC") or die("No direct access allowed!");

/* Make sure that the server uses PHP 7 */
if(!version_compare(PHP_VERSION,"7.0.0",">=")){
	throw new PuzzleError("Letsencrypt require PHP7!");
}

/* Register a function to perform CLI */
PuzzleCLI::register(function($io,$a){
	require_once("class.php");
	error_reporting($a["-v"] ? E_ERROR | E_WARNING : E_ERROR);
	
	ini_set('max_execution_time', 0); 
	if($a["-v"]) $io->out("Lets Encrypt Client\n");
	
	if($a["set"]){
		foreach($a as $k=>$v){
			if(substr($k,0,2) == "--"){
				if($a["-v"]) $io->out("$k=$v\n");
				LE\Config::store(substr($k,2),$v);
			}
		}
		if($a["-v"]) $io->out("Done\n");
	
	}else if($a["deactivate"]){
		if($a["-v"]) $io->out("Deactivating account...\n");
		$le_email = LE\Config::get("email");
		$wd = LE\Config::get("dir");
		$common_name = $a["--cn"];
		
		if(!file_exists($wd))
			throw new PuzzleError("Please set the correct path for working directory using\n\t'php puzzleos letsencrypt set --dir \"/var/html/cert\"");
		else{
			@mkdir("$wd/$common_name");
			$wd .= "/$common_name";
		}
		
		if(!filter_var($le_email,FILTER_VALIDATE_EMAIL))
			throw new PuzzleError("Please set the correct email address using\n\tphp puzzleos letsencrypt set --email you@example.com");
		if($common_name == "")
			throw new PuzzleError("Please specify common name using --cn");

		//Revoking account on LE
		$client = new LEClient(
			$le_email,
			$a["-temp"] ? true : false, 
			$a["-v"] ? LEClient::LOG_STATUS : LEClient::LOG_OFF,
			$wd
		);
		
		$acct = $client->getAccount();
		$acct->deactivateAccount();
		IO::remove_r($wd . "/__account");
		if($a["-v"]) $io->out("DONE...\n");
	}else if($a["reset"]){		
		//Removing old configuration and old account		
		$wd = LE\Config::get("dir");
		UserData::remove("cnf");
		@IO::remove_r($wd . "/__account");
		if($a["-v"]) $io->out("Done\n");
	}else if($a["revoke"]){
		$common_name = $a["--cn"];
		$domains = explode(",",$a["--domains"]);		
		$le_email = LE\Config::get("email");
		$wd = rtrim(str_replace("\\","/",LE\Config::get("dir")),"/");
		
		if(!file_exists($wd))
			throw new PuzzleError("Please set the correct path for working directory using\n\t'php puzzleos letsencrypt set --dir \"/var/html/cert\"");
		else{
			@mkdir("$wd/$common_name");
			$wd .= "/$common_name";
		}
		
		if(!filter_var($le_email,FILTER_VALIDATE_EMAIL)) 
			throw new PuzzleError("Please set the correct email address using\n\tphp puzzleos letsencrypt set --email you@example.com");
		if(count($domains) == 0) 
			throw new PuzzleError("Domains cannot be empty! If you want to create SN, use comma as separator");
		if($common_name == "")
			throw new PuzzleError("Please specify common name using --cn");
		
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
			$a["-temp"] ? true : false, 
			$a["-vv"] ? LEClient::LOG_DEBUG : ($a["-v"] ? LEClient::LOG_STATUS : LEClient::LOG_OFF),
			$wd
		);
		
		if($a["-v"]) $io->out("LE Created...\n");
		
		$order = $client->getOrCreateOrder($common_name,$domains);
		if($a["-v"]) $io->out("Order Created...\n");
		
		if($order->revokeCertificate()){
			$io->out("OK!\n");
		}else{
			throw new PuzzleError("Cannot revoke certificate!");
		}
		
	}else if($a["order"]){
		if($a["-v"]) $io->out("Ordering certificate...\n");
		
		$common_name = $a["--cn"];
		$domains = explode(",",$a["--domains"]);
		$le_email = LE\Config::get("email");
		$wd = rtrim(str_replace("\\","/",LE\Config::get("dir")),"/");
		
		if(!file_exists($wd))
			throw new PuzzleError("Please set the correct path for working directory using\n\t'php puzzleos letsencrypt set --dir \"/var/html/cert\"");
		else{
			@mkdir("$wd/$common_name");
			$wd .= "/$common_name";
		}
		if(!filter_var($le_email,FILTER_VALIDATE_EMAIL)) 
			throw new PuzzleError("Please set the correct email address using\n\tphp puzzleos letsencrypt set --email you@example.com");
		if(count($domains) == 0) 
			throw new PuzzleError("Domains cannot be empty! If you want to create SN, use comma as separator");
		if($common_name == "")
			throw new PuzzleError("Please specify common name using --cn");
			
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
			$a["-temp"] ? true : false, 
			$a["-vv"] ? LEClient::LOG_DEBUG : ($a["-v"] ? LEClient::LOG_STATUS : LEClient::LOG_OFF),
			$wd
		);
		
		if($a["-v"]) $io->out("[OK] LE Created...\n");
		
		LE\CF::init();
		LE\CF::chZone($common_name);
		
		if($a["-v"]) $io->out("[OK] Cloudflare Connection...\n");
		
		$order = $client->getOrCreateOrder($common_name,$domains);
		if($a["-v"]) $io->out("[OK] Order Created...\n");
		
		if(!$order->allAuthorizationsValid()){
			$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
			if($pending !== false){
				if($a["-v"]) {
					print_r($pending);
					$io->out(count($pending)." authorization needed...\n");
				}
				foreach($pending as $k=>$d){
					$subdomain = ltrim(rtrim("_acme-challenge." . str_replace($common_name,"",$d["identifier"]),"."),".");
					
					if($a["-v"]) $io->out("Validating $subdomain with key {$d["DNSDigest"]} #$k...\n");
					
					if(LE\CF::add($d["DNSDigest"], $d["identifier"]) === false) throw new PuzzleError("Cannot add DNS TXT record");
					
					if($a["-v"]){
						for ($i=125 ; $i>0 ; $i--) {
						  echo "Delaying $i secs, waiting for DNS cache to flush...\r";
						  sleep(1);
						}
						$io->out("Delaying 0 secs, waiting for DNS cache to flush...\r\n");
					}else{
						sleep(125);
					}
					
					if($a["-v"]) $io->out("Validating now #$k...\n");
					
					$ver_challenges = $order->verifyPendingOrderAuthorization($d["identifier"], LEOrder::CHALLENGE_TYPE_DNS, false);
					if($ver_challenges !== true){
						throw new PuzzleError("Failed to verify ACME Challenge on {$d["identifier"]} with key {$d["DNSDigest"]}");
					}
					
					if($a["-v"]) $io->out("Validated #$k...\n");
					if($a["-v"]) $io->out("Deleting record #$k...\n");
					LE\CF::rm($d["identifier"]);
				}
			}
		}
		
		if($order->allAuthorizationsValid()){
			if($a["-v"]) $io->out("Getting certificate...\n");
			if(!$order->isFinalized()) $order->finalizeOrder();
			if($order->isFinalized()) $order->getCertificate();
			$io->out("OK!\n");
		}else{
			$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
			print_r($pending);
		}
	}
});
?>