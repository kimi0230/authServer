# Token Authorization

Base on OAuth2 and JWT to implement authorization system.

### Download Consul
https://www.consul.io/downloads

#### Star consul
```sh
mv consul /usr/local/bin/
consul agent -dev
```

####  consul server
http://localhost:8500

### Install package
```sh
go mod tidy
```

### Acquire Token flow
#### 1. Create Token
* Authorization is `clientId:clientSecret` to base64, so it is `Y2xpZW50SWQ6Y2xpZW50U2VjcmV0` 
* username is `simaple` or `admin`
* both password are `123456`

##### Reqest
``` bash
curl --location --request POST 'http://localhost:10098/oauth/token' \
--header 'Content-Type: multipart/form-data' \
--header 'Host: localhost:10098' \
--header 'Authorization: Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0' \
--form 'username="simple"' \
--form 'password="123456"'
```

##### Response
``` json
{
    "access_token": {
        "RefreshToken": {
            "RefreshToken": null,
            "TokenType": "jwt",
            "TokenValue": "...",
            "ExpiresTime": "2021-02-28T22:00:45.703028+08:00"
        },
        "TokenType": "jwt",
        "TokenValue": "...",
        "ExpiresTime": "2021-02-28T17:30:45.703072+08:00"
    },
    "error": ""
}
```

#### 2. Check Token
##### Reqest
``` bash
curl --location --request POST 'http://localhost:10098/oauth/check_token?token=...' \
--header 'Authorization: Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0' \
--header 'Host: localhost:10098'
```

##### Response
``` json
{
    "o_auth_details": {
        "Client": {
            "ClientId": "clientId",
            "ClientSecret": "",
            "AccessTokenValiditySeconds": 1800,
            "RefreshTokenValiditySeconds": 18000,
            "RegisteredRedirectUri": "http://127.0.0.1",
            "AuthorizedGrantTypes": [
                "password",
                "refresh_token"
            ]
        },
        "User": {
            "UserId": 1,
            "Username": "simple",
            "Password": "",
            "Authorities": [
                "Simple"
            ]
        }
    },
    "error": ""
}
```

#### 3. Refresh Token if Token is invalid
##### Reqest
``` bash
curl --location --request POST 'http://localhost:10098/oauth/token?grant_type=refresh_token&refresh_token=...' \
--header 'Authorization: Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0' \
--header 'Host: localhost:10098' \
--header 'Content-Type: multipart/form-data'
```
##### Response
``` json
{
    "access_token": {
        "RefreshToken": {
            "RefreshToken": null,
            "TokenType": "jwt",
            "TokenValue": "...",
            "ExpiresTime": "2021-02-28T17:29:23.65741+08:00"
        },
        "TokenType": "jwt",
        "TokenValue": "...",
        "ExpiresTime": "2021-02-28T17:26:43.657444+08:00"
    },
    "error": ""
}
```

### Call APIs
#### Get Simple
##### Reqest
``` bash
curl --location --request GET 'http://localhost:10098/simple' \
--header 'Authorization: ...' \
--header 'Cache-Control: no-cache' \
--header 'Host: localhost:10098'
```
##### Response
```
{
    "result": "hello simple ,simple data, with simple authority",
    "error": ""
}
```
#### Get Admin
##### Reqest
``` bash
curl --location --request GET 'http://localhost:10098/admin' \
--header 'Authorization: ...' \
--header 'Cache-Control: no-cache' \
--header 'Host: localhost:10098'
```
##### Response
```
{
    "result": "hello admin ,admin data, with admin authority",
    "error": ""
}
```

### [Prometheus](https://prometheus.io/)
http://localhost:10098/metrics

Prometheus is a systems and service monitoring system. It collects metrics from configured targets at given intervals, evaluates rule expressions, displays the results, and can trigger alerts when specified conditions are observed.Visit [prometheus.io](https://prometheus.io/) for the full documentation, examples and guides.

### Reference
* https://github.com/longjoy/micro-go-book