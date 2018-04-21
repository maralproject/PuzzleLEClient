# PuzzleLEClient
Another PuzzleOS apps to integrate Let's Encrypt ACME v2 client
A simple client tool for PuzzleOS to manage and automatically renew
Let's Encrypt certificate with DNS-01 challenge provided by Cloudflare.
- Require [PuzzleOS](https://github.com/maralproject/puzzleos) with PHP7+

## Note
- Since verification is using cloudflare DNS-01 challenge, ordering new certificate require up to 120s * the number of domain. (Use -v for more info)
- When you want to revoke, make sure you put the correct domain order in the exact same order as you order the certificate in the first place.
- All transaction happend in the staging server. When you're ready, add `-live` to execute it on the active ACME v2 server

## Usage:
```
sudo -u www-data php puzzleos letsencrypt [set|revoke|order] [options] [-live] [-v] [-vv]
```

## Options:
```
set --email someone@example.com               Set email to be associated with Let's Encrypt
set --cloudflare-email someone@example.com    Set Cloudflare email address
set --cloudflare-api <Cloudflare API>         Set Cloudflare API key
set --dir /path/to/cert/dir                   Set directory where certificate will be stored later

revoke --cn example.com --domains "*.example.com,example.com"                Revoke certificate
order --cn example.com --domains "*.example.com,example.com" [-autorenewal]  Order or reissue certificate
	 
disable-renewal --cn example.com 
```
