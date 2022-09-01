# getssl.py
A python script to get SSL certificate for ACME v2 protocol with DNSPod API

## Usage
```bash
python getssl.py <configPath> <domain>
```

`<domain>` refers to the `COMMON_NAME` that need the certificate.

Certificate private key will be saved with a passphrase.

## Config File
```json
{
  "ca": "ACME server directory",
  "ca": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "dnspod": "DNSpod API URL",
  "dnspod": "https://dnsapi.cn",
  "accountKey": "ACME account key",
  "accountKey": "~/.ssh/id_rsa",
  "dnspodToken": "DNSPod token (= id,token)",
  "dnspodToken": "123456,*********************",
  "baseDomain": "Base domain in dnspod",
  "baseDomain": "xyz.org",
  "workingDir": "Working directory to save the certs.",
  "workingDir": "Each cert is identified by domain and date.",
  "workingDir": "Note that cert with same domain and signed in the same date will overwrite previous one.",
  "workingDir": "~/.ssl"
}
```

## Limitations

- Only support DNSPod API v2
- Only support ACME v2
- Only support RSA key for both ACME account key and cert private key. This is because some EC CAs from letsencrypt are not in the trusted list for some browsers.

## Author

Tiny
