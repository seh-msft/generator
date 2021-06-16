# Generator

Generator builds complete HTTP requests from an OpenAPI specification. 

Requires a [cfg](https://github.com/seh-msft/cfg) file populated with identifier values for the specification. 

The [cfgutil tool](https://github.com/seh-msft/cfgutil) can be used to generate cfg files from OpenAPI specification files. 

Some scripts - such as *doall* - leverage [jsonfs](http://github.com/droyo/jsonfs) and expect it to be in their `PATH`. 

Written in [Go](https://golang.org). 

## Build

	go build

## Database format

The text file format is as per [cfg](https://github.com/seh-msft/cfg):

```
# Alice's identifiers

someId=abc-123-def-321
      disallow regex title=".*" path=".*"                                            # Disallow by default
	permit regex title="Some.API.Set*" title="Accounts v[1-3]"
      permit path="/somewhere/myapi" path="/nowhere/yourapi/{someId}" title="foo"

anotherId=qrf-426-ori-253
      disallow regex "ABC*"

profileNumber=92058205
	disallow title="Some APIs" title="Not-Your-API"

tenant=456-768-675-209
	disallow regex path=".*/accessible"   # Disallowed for paths in the form `*/accessible` such as `"/foo/accessible"`
	permit regex title="ABC*"           # Allowed for all APIs titled "ABC …" like "ABC Accounts v3"

tenant=678-231-235-764

index=            # This value intentionally left blank, this is not a mistake
      properties fuzz

number=
      values 2 4 6 8
```

Lines other than the `id=value` line are optional.

`permit` implies that the identifier is valid for attributes listed. 

`disallow` implies that the identifier is invalid for attributes listed.

As such, the restriction mechanism is restrict first (`disallow`), then add caveats (`permit`). 

`permit` and `disallow` have an optional attribute, `regex`, which asserts all entries on a line are regular expressions as per [Go's "regexp" package](https://golang.org/pkg/regexp/) for matching. 

Interactive testing of regular expression validity may be convenient through [The Go Playground](https://play.golang.org/p/fAOtlAULSj8). 

The attribute name `title` indicates the `"title":` field value of an OpenAPI specification. 

The attribute name `path` indicates the `"path":` field of an OpenAPI specification. 

Omission of both `permit` and `disallow` implies that an identifier is valid for all paths of all API's. 

A single `permit` or `disallow` tuple (line) is binding to that line and represents a single rule. For example, if two `title` and one `path` attributes share a `permit` tuple, then that tuple implies that across two `title` entries one `path` is valid under both `title`s. 

For a given identifier to be returned in the set of results, the identifier must not fulfill any `disallow` tuple and must fulfill at least one `permit` tuple. 

A global dissolution `disallow` tuple with one valid `path` on any API would resemble:

```
someId=abc-123-def-567
      disallow regex title=".*" path=".*"
      permit path="/foo/{someId}"
```

`properties` is a list of keys indicating how substitution may be performed. 

i.e. the path `/move/{tenant}/{tenant}?object={someId}` would become `/move/456-768-675-209/678-231-235-764?object=abc-123-def-321` for the above cfg. 

The `fuzz` property instructs *generator* to randomly generate a valid-typed value for an identifier. 

`values` instructs *generator* to select a value from the list of values. The selection from the list of values is sequential within a section of a request. If combined with the `fuzz` property, a value will be chosen at random.

**Disclaimer**: At the time of writing, `fuzz` is not fully implemented and there's no sequencing of values done. Only the first value is taken for sets of results and further functionality will come later. Fuzz may be removed from the spec in the future. 

## Usage

```
Usage of generator:
  -D    verbose logging output
  -ado
        Use ADO output mode for replay results
  -allbodies
        force writing a body for ALL requests
  -api string
        OpenAPI JSON file to parse
  -auth string
        'Authorization: Bearer' header token value
  -cert string
        Certificate (if listening HTTPS)
  -db string
        key=value database to read identifiers from
  -ignoremethods string
        HTTP methods to not build (PUT,PATCH)
  -key string
        Private key (if listening HTTPS)
  -listen string
        TCP port to listen on for HTTP (if any)
  -noauth
        Strip Authorization: and Cookie: headers
  -noreplay
        Do not replay built requests
  -o string
        file name to write output to (default "-")
  -printreqs
        log HTTP bodies
  -proto string
        HTTP protocol to use (default "https")
  -strict
        if a value can't be filled, fail
  -target string
        Hostname to force target replay to
```

## Scripts

Many supporting scripts are written in the [rc](https://github.com/rakitzis/rc) shell under WSL. 

Rc can be installed on Debian-like systems with `sudo apt-get install rc`. 

* doall — takes a directory of OpenAPI v3 `.json` files and runs generator on them

Note that none of the scripts are mandatory for this tooling to work, they simply demonstrate automation of generator. 

## Examples

Generate requests with auth:

```
$ go run generator.go -auth $(getbearer) -api specification.json -db alice.cfg
…
$ 
```

Generate requests from the OpenAPI JSON file `myapi.json` to called using identifiers for Alice from `alice.cfg` to be run as Bob via the OAuth token `Bearer xyz` and pretty-print results:

```
$ go run generator.go -auth "xyz" -api myapi.json -db alice.cfg  | jq .
[
  "GET /accounts/me/address HTTP/1.1\r\nHost: something.somewhere\r\nAuthorization: Bearer xyz\r\n\r\n",
  "GET /accounts/123-321 HTTP/1.1\r\nHost: something.somewhere\r\nAuthorization: Bearer xyz\r\n\r\n",
  "GET /accounts/123-321/about HTTP/1.1\r\nHost: something.somewhere\r\nAuthorization: Bearer xyz\r\n\r\n",
  "GET /accounts/123-321/status HTTP/1.1\r\nHost: something.somewhere\r\nAuthorization: Bearer xyz\r\n\r\n",
  "GET /accounts/123-321/accessible HTTP/1.1\r\nHost: something.somewhere\r\nAuthorization: Bearer xyz\r\n\r\n",
  "POST /accounts/123-321/update HTTP/1.1\r\nHost: something.somewhere\r\nAuthorization: Bearer xyz\r\n\r\n"
]
generator$
```
