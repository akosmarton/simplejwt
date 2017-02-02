# simplejwt
A simple [JSON Web Tokens](https://jwt.io/) package in Go

# Description
You can easly add JWT authentication with the help of this package to your golang web application.

## Examples
### Generate New Token
To generate a new token, use NewToken():
```
f := make(map[string]interface{})

f["iat"] = time.Now().UTC().Unix()
f["exp"] = time.Now().UTC().Add(time.Hour).Unix()
f["nbf"] = time.Now().UTC().Add(-time.Minute).Unix()

t, err := simplejwt.NewToken(&f, []byte("very-secret-password"))
```
### Parse and Verify Token
To parse and verify a token, use ParseToken():
```
_, ok, err := ParseToken(t, []byte("very-secret-password"))
```
In this example, the value of **ok** should be **true** if the token is valid.
## Remarks
Only HS256 hash algorithm is supported at the moment.

## Installation
```
go get -u github.com/akosmarton/simplejwt
```
