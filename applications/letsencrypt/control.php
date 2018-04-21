<?php
defined("__POSEXEC") or die("No direct access allowed!");

if(__getURI("app") == "letsencrypt") redirect();
?>