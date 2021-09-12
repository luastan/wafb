# WAF Bypass

Easily find origin servers behind WAFs.

## Usage

Basic usage:
```shell
cat ips.txt | wafb https://example.com/
```
Directly specify the list via an argument:

```shell
wafb -l ips.txt https://example.com/
```

The tool will automatically parse networks/ranges in the list. No need to specify every IP in a block as the tool will test every IP on it. The following would be an example of valid inputs:
```
192.168.0.0/24
192.168.0.1-192.168.0.255
192.168.0.1 -   192.168.0.255
192.168.0.44
```

**Proxy support:** The tool supports the use of a proxy. HTP and SOCKS5 are accepted:

```shell
wafb -l ips.txt https://example.com/ -proxy https://localhost:8080
```

```shell
wafb -l ips.txt https://example.com/ -proxy socks5://localhost:1337
```

**Cookies:** Many WAFs use cookies to distinguish valid requests from those considered to have DoS potential (Mainly any form of automated requests). Add your browser cookies as follows:
```shell
wafb -l ips.txt https://example.com/ -c "incap_ses_XX=AAAA; incap_ses_YY=BBBB"
```

**Routes:** You can check different routes other than `/`. If you want to check `/content` you can directly specify it:
```shell
wafb -l ips.txt https://example.com/content
```

**Status codes:** The tool discards responses with status codes other than 2xx. You can whitelist other status codes:
```shell
wafb -l ips.txt https://example.com/error -s "404,403,502"
```

**Timeout:** Addresses that lead to timeouts are discarded. By default the tool waits 10 seconds, which can be changed as follows:
```shell
wafb -l ips.txt https://example.com/error -t 5s
```

## Installation

With ``go install``:

```shell
go install github.com/luastan/wafb@latest
```

## TODOs

 - [ ] Make some unit tests to verify the parsing is done correctly
 - [ ] Allow multiple comparison methods to find similarity between requests
 - [ ] Add a parameter to only show IPs with more than X% coincidence with the original request
 - [ ] Add IPv6 support
 - [ ] Allow custom user agent or custom Headers
 - [ ] Allow checking on different ports. Maybe origin server only listens to port 80
 - [ ] Instead of just parsing the entire file and storing every IP on memory, maybe adding a goroutine that reads little by little and sends addresses through a channel