<?php
/* Register a cron job to renew old certificate */
$ct = new CronTrigger;
$ct->interval(T_DAY);

CronJob::register("renew", function () {
	if (defined("__POSCLI")) {
		$io = new PObject([
			"in" => function () {
				if (PHP_OS == 'WINNT')
					$line = stream_get_line(STDIN, 1024, PHP_EOL);
				else
					$line = readline();

				return $line;
			},
			"out" => function ($o) {
				echo trim($o, "\t");
				file_put_contents(__ROOTDIR . "/letsencrypt.log", $o, FILE_APPEND);
			}
		]);
	} else {
		$io = new PObject([
			"in" => function () {
				throw new PuzzleError("Input only available in CLI!");
			},
			"out" => function ($o) {
				file_put_contents(__ROOTDIR . "/letsencrypt.log", $o, FILE_APPEND);
			}
		]);
	}

	require("class.php");

	$db = Database::readAll("app_letsencrypt_cert", "where `nextIssue`<'?'", time());
	if (count($db) > 0) $io->out("Renewing Let's Encrypt certificate...\n");
	$dir = realpath(rtrim(btfslash(LE\Config::get("dir")), "/"));
	foreach ($db as $d) {
		$io->out("Renewing " . $d["cn"] . "...\n");
		$domains = explode(",", $d["domains"]);
		LE\ACME::recursiveRemoveDirectory("$dir/{$d["cn"]}");
		$client = LE\ACME::getInstance($d["cn"], $d["live"] == 1 ? false : true, LEClient\LEClient::LOG_STATUS);
		if (LE\ACME::order($client, $d["cn"], $domains, $io, true, true)) {
			$io->out("OK!\n");
		}
	}
	if (count($db) > 0) $io->out("Nothing to renew!\n");
}, $ct);

/* Register a function to perform CLI */
PuzzleCLI::register(function ($io, $a) {
	require("class.php");
	POSConfigGlobal::$error_code |= $a["-v"] ? E_ERROR | E_WARNING : E_ERROR;

	ini_set('max_execution_time', 0);
	$io->out("\nLet's Encrypt Client\n");

	if ($a["set"]) {
		foreach ($a as $k => $v) {
			if (substr($k, 0, 2) == "--") {
				if ($a["-v"]) $io->out("$k=$v\n");
				LE\Config::store(substr($k, 2), $v);
			}
		}
		if ($a["-v"]) $io->out("Done\n");

	} else if ($a["revoke"]) {
		if ($a["-v"]) $io->out("Revoking certificate...\n");
		if ($a["-v"]) if ($a["-live"] !== true) $io->out("Use staging server...\n");

		$common_name = $a["--cn"];
		$domains = explode(",", $a["--domains"]);

		$client = LE\ACME::getInstance($common_name, $a["-live"] ? false : true, $a["-vv"] ? LEClient\LEClient::LOG_DEBUG : ($a["-v"] ? LEClient\LEClient::LOG_STATUS : LEClient\LEClient::LOG_OFF));
		if ($a["-v"]) $io->out("LE Created...\n");

		if (LE\ACME::revoke($client, $common_name, $domains, $io, $a["-v"])) {
			if (!$a["-v"]) $io->out("OK!\n");
		}

	} else if ($a["disable-renewal"]) {
		//Removing autorenewal
		Database::delete("app_letsencrypt_cert", "cn", $a["--cn"]);
		$io->out("OK!\n");

	} else if ($a["order"]) {
		if ($a["-v"]) $io->out("Ordering certificate...\n");
		if ($a["-v"]) if ($a["-live"] !== true) $io->out("Use staging server...\n");

		$common_name = trim($a["--cn"]);
		$domains = explode(",", $a["--domains"]);

		$client = LE\ACME::getInstance($common_name, $a["-live"] ? false : true, $a["-vv"] ? LEClient\LEClient::LOG_DEBUG : ($a["-v"] ? LEClient\LEClient::LOG_STATUS : LEClient\LEClient::LOG_OFF));
		if ($a["-v"]) $io->out("[OK] LE Created...\n");

		if (LE\ACME::order($client, $common_name, $domains, $io, $a["-autorenewal"], $a["-v"])) {
			if (!$a["-v"]) $io->out("OK!\n");
		}
	} else {
		include("help_cli.php");
	}
});