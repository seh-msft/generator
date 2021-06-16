// Copyright (c) 2021, Microsoft Corporation, Sean Hinchee
// Licensed under the MIT License.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/seh-msft/cfg"
	"github.com/seh-msft/openapi"
)

// Result indicates the type of result of a lookup
type Result int

const (
	something Result = iota // Something was found (1+ results)
	nothing                 // Nothing was found
	fuzzing                 // The caller should invoke contextual fuzzing
)

// RequestStrings is a table of HTTP requests to emit
// For serialization
type RequestStrings struct {
	Requests []string
}

// Request represents an HTTP request and associated meta-information.
type Request struct {
	*http.Request                 // HTTP request
	Method        *openapi.Method // Method related to our request
}

var (
	auth          = flag.String("auth", "", "'Authorization: Bearer' header token value")
	apiName       = flag.String("api", "", "OpenAPI JSON file to parse")
	dbName        = flag.String("db", "", "key=value database to read identifiers from")
	chatty        = flag.Bool("D", false, "verbose logging output")
	printReqs     = flag.Bool("printreqs", false, "log HTTP bodies")
	strict        = flag.Bool("strict", false, "if a value can't be filled, fail")
	proto         = flag.String("proto", "https", "HTTP protocol to use")
	outName       = flag.String("o", "-", "file name to write output to")
	allBodies     = flag.Bool("allbodies", false, "force writing a body for ALL requests")
	port          = flag.String("listen", "", "TCP port to listen on for HTTP (if any)")
	cert          = flag.String("cert", "", "Certificate (if listening HTTPS)")
	key           = flag.String("key", "", "Private key (if listening HTTPS)")
	noReplay      = flag.Bool("noreplay", false, "Do not replay built requests")
	ado           = flag.Bool("ado", false, "Use ADO output mode for replay results")
	ignoreMethods = flag.String("ignoremethods", "", "HTTP methods to not build (PUT,PATCH)")
	noAuth        = flag.Bool("noauth", false, "Strip Authorization: and Cookie: headers")
	target        = flag.String("target", "", "Hostname to force target replay to")

	stderr *bufio.Writer
)

// Generator is a tool to generate HTTP requests from an OpenAPI specification.
func main() {
	flag.Parse()

	stderr = bufio.NewWriter(os.Stderr)
	defer stderr.Flush()

	// TODO - output file flag
	var out *bufio.Writer = bufio.NewWriter(os.Stdout)
	defer out.Flush()

	// Generator As A Service
	// TODO - propagate flags as setting defaults for listener?
	if *port != "" {
		if (*cert != "" || *key != "") && (*cert == "" || *key == "") {
			fatal("err: if using TLS, both -key and -cert must be provided")
		}
		listen(*port, *cert, *key)
		return
	}

	// TODO - 'Cookie:' header
	if (*auth == "" && !*noAuth) || *apiName == "" || *dbName == "" {
		fatal("err: must supply all of -auth, -api, and -db ")
	}

	f, err := os.Open(*apiName)
	if err != nil {
		fatal("err: could not open API file →", err)
	}

	api, err := openapi.Parse(f)
	if err != nil {
		fatal("err: could not parse API →", err)
	}

	// Override target
	if *target != "" {
		api.Servers = []openapi.Server{{URL: *target}}
	}

	// Remove relevant methods from API signatures
	if len(*ignoreMethods) > 0 {
		for _, method := range strings.Split(*ignoreMethods, ",") {
			for _, methods := range api.Paths {

				down := strings.ToLower(method)
				delete(methods, down)
			}
		}
	}

	db := ingestDb(*dbName)
	// Insert authorization
	// TODO - Make cleaner as per https://github.com/seh-msft/cfg/issues/1
	if !*noAuth {
		// TODO - this might need to be stubbed for after to permit api path building
		db.Records = append(db.Records, &cfg.Record{Tuples: []*cfg.Tuple{{Attributes: []*cfg.Attribute{{Name: "Authorization", Value: "Bearer " + *auth}}}}})
	}
	db.BuildMap()

	requests, missing, totalPossible, err := generate(api, db)
	if err != nil {
		fatal("fatal: generation failed ⇒ ", err)
	}

	chat(fmt.Sprintf("Built %d/%d requests (%.0f%%)\n", len(requests), totalPossible, 100*(float64(len(requests))/float64(totalPossible))))
	chat(fmt.Sprintf("Parameters missed: %v\n", missing))

	// If we don't replay, emit built requests
	if *noReplay {
		enc := json.NewEncoder(out)
		enc.Encode(requests2strings(requests))
		return
	}

	// Optionally replay requests
	results := make(map[*Request]*Response)
	for _, request := range requests {
		resp := replay(request.Request, nil)
		results[request] = &resp
	}

	// Optionally validate against spec
	sus, ok, err := validate(results)

	// Emit ADO format
	if *ado {
		printADO(out, requests, missing, sus, ok)
		return
	}

	// Emit as JSON by default
	err = printJSON(out, requests, missing, sus, ok)
	if err != nil {
		fatal("err: could not marshal requests →", err)
	}

	out.Flush()
}

// Convert []requests → []string
func requests2strings(requests []*Request) RequestStrings {
	var reqStrings []string
	for _, request := range requests {
		reqStrings = append(reqStrings, prettyRequest(request.Request))

		if *printReqs {
			emit(prettyRequest(request.Request) + "\n\n")
		}
	}
	return RequestStrings{reqStrings}
}

// Do generation step, all we need is an api and a db
func generate(api openapi.API, db cfg.Cfg) ([]*Request, map[string]uint64, uint64, error) {

	failed := make(map[string]error)
	var requests []*Request
	totalPossible := uint64(0)
	missing := make(map[string]uint64)

	// "/foo/bar", map["get"]Method{}
	for path, methods := range api.Paths {
		chat(path + ":\n")

		// "get", Method{}
	methods:
		for httpMethod, method := range methods {
			totalPossible++
			// TODO - openapi parse "requestBody" for POST, etc.
			chat("\t" + httpMethod + ":\n")

			chat("\t\t" + method.Summary + "\n\n")

			// Were all the parameters filled from the db?
			var paths, queries, headers []openapi.Parameter
			var body bytes.Buffer

			// Scan parameters for where they will be substituted in the request to build
			// Parameter.In = "path", "query", or "header"
			for _, param := range method.Parameters {
				if !param.Required {
					// TODO - attempt to fill non-required parameters
					// Might be non-trivial
					continue
				}

				switch strings.ToLower(param.In) {
				case "path":
					paths = append(paths, param)

				case "query":
					queries = append(queries, param)

				case "header":
					headers = append(headers, param)
				}

				chat("\t\t" + param.In + " — " + param.Name + "\n")
			}

			// Insert path parameters
			// TODO - build URL/request for each server if multiple servers exist
			if len(api.Servers) < 1 {
				return nil, nil, 0, errors.New("err: need at least one server to call, none provided")
			}

			fullPath := *proto + api.Servers[0].URL + path
			for _, parameter := range paths {
				values, r := lookup(db, parameter.Name, path, api.Info.Title)
				switch r {
				case something:
					apiForm := fmt.Sprintf(`{%s}`, parameter.Name)
					// TODO - sequencing
					fullPath = strings.ReplaceAll(fullPath, apiForm, values[0])

				case nothing:
					if *strict {
						return nil, nil, 0, errors.New("err: could not find path parameter →" + parameter.Name)
					}

					missing[parameter.Name]++
					failed[path] = errors.New(fmt.Sprint("could not find query parameters → ", parameter))
					continue methods
				case fuzzing:
					// TODO - fuzz - maybe should remove this 'feature' skeleton
				default:
				}
			}

			// Build body, if required
			if method.RequestBody.Required || *allBodies {
				// TODO - break out different formats
				ref := method.RequestBody.Content["application/json"]["schema"].Ref
				// We get #/components/schemas/ as a prefix sometimes
				refLess := strings.TrimPrefix(ref, "#/components/schemas/")

				found := false
				var target openapi.Type

				// Find our definition by ref
			search:
				// All types in the schema table
				for typeName, t := range api.Components["schemas"] {

					// Properties are elements in the body
					for _, property := range t.Properties {
						schema := property.Items
						if schema.Ref == ref || schema.Ref == refLess || typeName == ref || typeName == refLess {
							// We found our type ref
							target = t
							found = true

							break search
						}
					}
				}

				// Start constructing JSON for the body
				// TODO - an actual recursive object builder?
				//		"object" could trigger a new map[] level
				obj := make(map[string]string)
				if found {
					// We know the scheme, fill all we can
					for name, property := range target.Properties {
						// Fill values we know
						values, r := lookup(db, name, path, api.Info.Title)
						switch r {
						case something:
							// TODO - sequencing?
							obj[name] = values[0]

						case nothing:
							fallthrough
						case fuzzing:
							obj = randProperty(obj, name, property)
						}
					}
				} else {
					// Unknown scheme - let object be {}
					// TODO - strict mode fatal?
				}

				enc := json.NewEncoder(&body)
				enc.Encode(obj)
			}

			// Generate request structure
			httpReq, err := http.NewRequest(strings.ToUpper(httpMethod), fullPath, &body)
			if err != nil {
				if *strict {
					return nil, nil, 0, errors.New("err: could not build request → " + err.Error())
				}

				failed[path] = err
				continue methods
			}

			// Insert query parameters
			vals := httpReq.URL.Query()
			for _, parameter := range queries {
				values, r := lookup(db, parameter.Name, path, api.Info.Title)
				switch r {
				case something:

					// TODO - sequencing/fuzzing?
					vals[parameter.Name] = []string{values[0]}

				case nothing:
					if *strict {
						return nil, nil, 0, errors.New("err: could not find query parameter → " + parameter.Name)
					}

					missing[parameter.Name]++
					failed[path] = errors.New(fmt.Sprint("could not find query parameters → ", parameter))
					continue methods

				case fuzzing:
					// TODO - fuzzing?
				}

			}
			httpReq.URL.RawQuery = vals.Encode()

			// Override HTTP headers
			for _, parameter := range headers {
				values, r := lookup(db, parameter.Name, path, api.Info.Title)

				switch r {
				case something:
					// TODO - sequencing
					httpReq.Header[parameter.Name] = []string{values[0]}

				case nothing:
					if *strict {
						return nil, nil, 0, errors.New("err: could not find header parameter → " + parameter.Name)
					}

					missing[parameter.Name]++
					failed[path] = errors.New(fmt.Sprint("could not find header parameter - ", parameter))
					continue methods
				case fuzzing:
					// TODO - fuzzing?
				}
			}

			requests = append(requests, &Request{httpReq, &method})
		}

		chat("\n")
	}

	return requests, missing, totalPossible, nil
}

// Lookup an identifier name for a given path in a given API
// Return the set of values which are usable and an 'ok' indicator
// Path should be in the original OpenAPI {someId} form
func lookup(c cfg.Cfg, name, path, title string) ([]string, Result) {
	//chat("≡ lookup ⇒ ", name, path, title)
	var out []string
	hasRegex := func(tuple *cfg.Tuple) bool {
		_, has := tuple.Map["regex"]
		return has
	}

	// The attributes for record 'name' with the tuple 'name'
	primaryAttributes, ok := c.Map[name][name]
	if !ok {
		return out, nothing
	}
	primaryValue, hasValue := primaryAttributes[name]
	if hasValue {
		// Only true if we contain at least one element
		hasValue = len(primaryValue) > 0
	}

	// Get properties for record 'name'
	properties, hasProperties := c.Map[name]["properties"]

	// Short circuit if 'name' has no rules and no enumerated values
	_, hasDisallows := c.Map[name]["disallow"]
	_, hasPermits := c.Map[name]["permit"]
	_, hasEnums := c.Map[name]["values"]

	if !hasValue && !hasEnums {
		// Value omitted for this identifier
		// TODO - maybe a flag to handle this case?
		return out, nothing
	}

	if !hasDisallows && !hasPermits && !hasEnums && hasValue {
		// Just the value
		return primaryValue, something
	}

	// Records are identified by the identifier name
	records, ok := c.Lookup(name)
	if !ok {
		return out, nothing
	}

	fuzz := false

	// Determine if the identifier is valid
	// We do costly lookups here to guarantee ordering of 'permit', 'disallow', and 'values'
	// As they are ordered and maps play with ordering
recordSearch:
	for _, record := range records {
		// Sees if the tuple set has a matching attribute
		match := func(tuples []*cfg.Tuple) bool {
			for _, tuple := range tuples {
				attributes := tuple.Attributes
				// Strip 'except' or 'permit'
				if len(attributes) > 1 {
					attributes = attributes[1:]
				}

				// Valid determines if a given attribute entry and our name/path/title are compatible
				valid := func(value, other string) bool {
					return value == other
				}

				// Use regex to test equality if requested
				if len(attributes) > 1 && hasRegex(tuple) {
					valid = func(value, other string) bool {
						regex, err := regexp.Compile(value)
						if err != nil {
							fatal(`err: could not compile regex "`+value+`" →`, err)
						}

						return regex.MatchString(other)
					}

					// Strip 'regex'
					attributes = attributes[1:]
				}

				result := false

				// Search attributes in the tuple
			searchAttributes:
				for _, attr := range attributes {
					test := ""
					switch attr.Name {
					case "title":
						test = title
					case "path":
						test = path
					default:
						// Unknown keyword
						// Skip
						continue searchAttributes
					}

					if valid(attr.Value, test) {
						// Valid and we had an invalid result
						result = true
					} else {
						// Invalid and result was true
						// A rule in the tuple was violated
						result = false
						break searchAttributes
					}
				}

				if result {
					return true
				}
			}

			// Do not match by default
			return false
		}

		exceptions, ok := record.Lookup("disallow")
		if ok && match(exceptions) {
			// We are an exception
			continue recordSearch
		}

		constraints, ok := record.Lookup("permit")
		if ok && !match(constraints) {
			// We are not in scope
			continue recordSearch
		}

		// Populate properties
		if hasProperties {
			if _, hasFuzz := properties["fuzz"]; hasFuzz {
				fuzz = true
			}
		}

		// Search for enumerated values - ordered
		values, ok := record.Lookup("values")
		var vals []string

		// Build table of enumerated values
		if ok {
			for _, tuple := range values {
				attributes := tuple.Attributes
				if len(attributes) > 1 {
					for _, v := range attributes[1:] {
						vals = append(vals, v.Name)
					}
				}
			}
		}

		// Insert an enumerated value if any was supplied, short circuit
		if len(vals) > 0 {
			if fuzz {
				// Select at random
				index, err := rand.Int(rand.Reader, big.NewInt(int64(len(vals))))
				if err != nil {
					fatal("err: could not rng for value fuzz -", err)
				}

				// One, single, randomly selected, value
				// TODO - just shuffle and append?
				out = append(out, vals[int(index.Int64())])
				continue recordSearch
			}

			// All values, in order
			out = append(out, vals...)
			continue recordSearch
		}

		// Insert the primary value for this identifier
		if !fuzz && len(primaryValue) > 0 {
			out = append(out, primaryValue...)
			continue recordSearch
		}

		// TODO - fuzzing?
	}

	r := nothing
	if fuzz {
		r = fuzzing
	} else if len(out) > 0 {
		r = something
	}

	return out, r
}
