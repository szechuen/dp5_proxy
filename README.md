dp5_proxy
=========
XMPP/Jabber proxy integrating the DP5 (Dagstuhl Privacy Preserving Presence Protocol P) cryptographic protocol as introduced at ShmooCon 2017

Install
-------
### Server
```bash
docker run -e DP5_HOSTNAME="dp5.szechuen.com" -e DP5_EMAIL="tan@szechuen.com" -e DP5_STAGING="false" -e DP5_REGSVR="dp5.szechuen.com:8443" -e DP5_ISREG="false" -e DP5_ISLOOKUP="true" -p 443:443 -p 8443:8443 szechuen/dp5_proxy:server
```

### Client
#### macOS (Adium supported)
```bash
brew install gmp ntl openssl python tor

mkdir dp5/build
cd dp5/build
OPENSSL_ROOT_DIR=/usr/local/opt/openssl cmake ..
OPENSSL_ROOT_DIR=/usr/local/opt/openssl make
cd ../..

GOPATH=~/go go get golang.org/x/net/proxy
GOPATH=~/go go build
tor &
./dp5_proxy
```
