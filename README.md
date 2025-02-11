# SSL encrypted and password protected bind shell written in Go

## Change password
``` bash
sed -E "s/[0-9a-z]{64}/$(echo -n '<NEW PASSWORD>' | sha256sum | tr -d ' -')/g" bind.go > tmp && mv tmp bind.go
```

## Connect from linux

``` bash
openssl s_client -connect 127.0.0.1:45778
socat OPENSSL:127.0.0.1:45778,verify=0 -
```
