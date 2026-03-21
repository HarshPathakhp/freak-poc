Good choice — FREAK is a great attack to demonstrate because it's conceptually clean. Here's how to set up the full environment:

## Step 1 — Apache Config

Modify your existing config to enable export-grade cipher suites:

```apache
ServerTokens Prod
ServerSignature Off

<VirtualHost *:443>

  ServerName localhost

  DocumentRoot /var/www/html/public

  SSLEngine on

  SSLCertificateFile    /etc/ssl/localcerts/selfsigned.crt
  SSLCertificateKeyFile /etc/ssl/localcerts/selfsigned.key

  # TLS 1.2 only
  SSLProtocol -all +TLSv1.2

  # Export-grade cipher suites
  SSLCipherSuite EXPORT:EXPORT40:EXPORT56

  # Server enforces its cipher preference
  SSLHonorCipherOrder on

  <Directory /var/www/html/public>
    AllowOverride All
    Require all granted
  </Directory>

  ErrorLog ${APACHE_LOG_DIR}/error-ssl.log
  CustomLog ${APACHE_LOG_DIR}/access-ssl.log combined

</VirtualHost>
```

---

## Step 2 — The Same OpenSSL Problem

Just like RC4, **modern OpenSSL has export ciphers disabled**. Check first:

```bash
# See if export ciphers are available
openssl ciphers -v 'EXPORT'

# Check your OpenSSL version
openssl version
```

- OpenSSL **< 1.0.2** → export ciphers available by default ✅
- OpenSSL **1.0.2 — 1.1.0** → disabled by default, may need recompile
- OpenSSL **1.1.0+** → completely removed ❌

So again, a **Docker container with an old OpenSSL** is your most reliable path.

---

## Step 3 — Docker Setup for Guaranteed Export Cipher Support

```dockerfile
FROM ubuntu:14.04

RUN apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-ssl \
    openssl

# Enable SSL module
RUN a2enmod ssl

# Generate self-signed cert
RUN mkdir -p /etc/ssl/localcerts && \
    openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/localcerts/selfsigned.key \
    -out /etc/ssl/localcerts/selfsigned.crt \
    -days 365 -nodes \
    -subj "/CN=localhost"

# Copy your apache config
COPY apache-freak.conf /etc/apache2/sites-available/default-ssl.conf

RUN a2ensite default-ssl

EXPOSE 443

CMD ["apache2ctl", "-D", "FOREGROUND"]
```

```bash
docker build -t freak-server .
docker run -p 4433:443 freak-server
```

---

## Step 4 — Verify Export Ciphers are Negotiable

```bash
# List what the server actually offers
nmap --script ssl-enum-ciphers -p 4433 localhost | grep -i export

# Try to negotiate an export cipher directly
openssl s_client \
    -connect localhost:4433 \
    -tls1_2 \
    -cipher EXP-RC4-MD5 \
    -no_tls1_3

# Look for:
# Cipher    : EXP-RC4-MD5
```

---

## Step 5 — How the FREAK Attack Works (For Your PoC Script)

```
Victim ──► Attacker (MITM) ──► Server
           rewrites ClientHello:
           removes strong suites,
           keeps only EXPORT suites
```

The attacker's proxy (same structure as your RC4 downgrade script) rewrites the `ClientHello` to advertise only export-grade suites. The key IDs to keep are:

```python
# Export cipher suite IDs to whitelist in the rewritten ClientHello
EXPORT_SUITES = [
    b'\x00\x03',  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
    b'\x00\x06',  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    b'\x00\x08',  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    b'\x00\x0B',  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA (DHE)
    b'\x00\x14',  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
]
```

Once the server agrees on an export suite, it sends a **512-bit RSA key** for key exchange. That 512-bit key can be **factored in under 7 hours** on modern hardware (or seconds on cloud infra), which lets the attacker:

1. Factor the 512-bit RSA modulus → recover the private key
2. Decrypt the `ClientKeyExchange` message → recover the pre-master secret
3. Derive the session keys
4. Decrypt the entire session

```
Timeline of a real FREAK attack:
  T+0s    → Downgraded handshake completes (export RSA key captured)
  T+~7hr  → 512-bit modulus factored (or seconds on AWS cluster)
  T+Xhr   → Pre-master secret recovered, session decrypted
```

---

## What Makes FREAK a Great Demo

It has a compelling backstory to present — export-grade ciphers were a **deliberate US government policy** in the 1990s (the "Crypto Wars"), requiring software exported outside the US to use intentionally weak 40-512 bit keys so the NSA could break them. The vulnerability lay dormant for decades until researchers discovered in 2015 that many modern servers still supported these ciphers, and modern clients could be tricked into requesting them — making it a **policy decision from the 90s becoming a live vulnerability in 2015**.