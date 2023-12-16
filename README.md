Dynamic DNS service for [mcu-app](https://github.com/nomis/mcu-app).

Assumes a mod_wsgi environment where the current working directory is a
private home directory, separate from the httpd document root.

The user database is PostgreSQL, with a separate password per hostname.

Requires a DNS service that uses zone files in a Git repositories (with
automatic serial handling on the server side). A separate zone is best
for dynamic DNS.

Requests are CBOR-encoded (RFC 8949) POST data of the form:
```
{"hostname": "...", "password": "...", "ip4": "...", "ip6": "..."}
```

Responses are CBOR-encoded, success:
```
[True]
```
or failure:
```
[False, "Error message"]
```

The client is expected to remember the previous IP addresses it used
and not make repeated requests after it is successful.
