====================
A simple client tool for PuzzleOS to manage and automatically renew
Let's Encrypt certificate with DNS-01 challenge provided by Cloudflare.

NOTE:
    -Since verification is using cloudflare DNS-01 challenge, ordering new
     certificate require up to 120s * the number of domain. (Use -v for more info)

    -When you want to revoke, make sure you put the correct domain order in
     the exact same order as you order the certificate.

USAGE:
     php puzzleos letsencrypt [set|revoke|order] [options] [-live] [-v] [-vv]
	 
OPTIONS:
     set --email someone@example.com               Set email to be associated with Let's Encrypt
     set --cloudflare-email someone@example.com    Set Cloudflare email address
     set --cloudflare-api <Cloudflare API>         Set Cloudflare API key
     set --dir /path/to/cert/dir                   Set directory where certificate will be stored later

     (Self explanatory)
     revoke --cn example.com --domains "*.example.com,example.com"
     order --cn example.com --domains "*.example.com,example.com" [-autorenewal]
	 
     disable-renewal --cn example.com

 
