$TTL 3600
$ORIGIN example.com.

@       IN      SOA     ns1.example.com. hostmaster.example.com. (
                        1
                        3600
                        600
                        86400
                        300
                        )

@       IN      NS      ns1.example.com.
@       IN      NS      ns2.example.com.
ns1     IN      A       192.0.2.1
ns2     IN      A       192.0.2.2

@       IN      MX      10 mail.example.com.
mail    IN      A       192.0.2.10

www     IN      A       192.0.2.100
www     IN      AAAA    2001:db8::100
@       IN      A       192.0.2.100

api     IN      A       192.0.2.50
app     IN      CNAME   api.example.com.

@       IN      TXT     "v=spf1 mx ip4:192.0.2.0/24 -all"

; Insecure delegation (NSEC3 opt-out)
insecure        IN      NS      ns1.insecure.example.com.
ns1.insecure    IN      A       192.0.2.200
