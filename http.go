// Copyright (c) 2021, Microsoft Corporation, Sean Hinchee
// Licensed under the MIT License.

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/seh-msft/cfg"
	"github.com/seh-msft/openapi"
)

// Response represents an HTTP response - omit the interface from "http" package
// For serialization
type Response struct {
	Status           string
	StatusCode       int
	Proto            string
	ProtoMajor       int
	ProtoMinor       int
	Header           http.Header
	Body             string
	ContentLength    int64
	TransferEncoding []string
	Close            bool
	Uncompressed     bool
	TLS              *tls.ConnectionState
}

// Set pairs a request and response for output formatting
type Set struct {
	*Request
	*Response
}

const utf8 = `<meta charset="utf-8">

`

// Handle '/' requests
func rootHandler(w http.ResponseWriter, r *http.Request) {
	splash := utf8 + `
<html>
<h1>Generator API</h1>

<p>You probably want to <code>POST /generator</code>.</p>
</html>
`
	w.Header().Add("Content-Type", "text/html")
	fmt.Fprint(w, splash)
}

// Handle '/gen' API requests
func genHandler(w http.ResponseWriter, r *http.Request) {
	type Options struct {
		Cfg     string `json:"cfg"`
		CfgPath string `json:"cfgpath"`
		API     string `json:"api"`
		Auth    string `json:"auth"`

		Target        string   `json:"target"`
		NoAuth        bool     `json:"noauth"`
		NoReplay      bool     `json:"noreplay"`
		IgnoreMethods []string `json:"ignoremethods"`
		ADO           bool     `json:"ado"`
	}
	var opts Options

	usage := `Usage via POST method:


__OPTIONS__


{
	"cfgpath":          string,            // URL for CFG file
	"cfg":              string,            // Literal CFG file string
	"api":              string,            // URL for OpenAPI JSON specification file
	"auth":             string,            // Authorization: Bearer [thispart]
	"target":           string,            // Hostname to replay built requests to
	"noauth":           bool,              // Strip Authorization: and Cookie: headers
	"noreplay":         bool,              // Do not replay built requests
	"ignoremethods":    array of string,   // HTTP methods to ignore (PUT, PATCH, etc.)
	"ado":              bool               // Use ADO output format for warnings, errors, etc. 
}

Required fields: (cfg ⊻ cfgpath) ∧ (auth ⊻ noauth) ∧ api


__EXAMPLES__


Minimum required fields:

{
	"cfgpath":"http://somewhere/path/to.cfg",
	"api":"http://somewhere/path/to/api.json",
	"auth":"eyzSomeKindOfOauthKeyForAuth"
}

Pass the literal CFG, change the target, don't use any auth:

{
	"cfg":"a=b\nc=d",
	"api":"http://somewhere/path/to/api.json",
	"auth":"",
	"noauth": true,
	"target": "1.2.3.4"
}

Don't replay and ignore PUT and PATCH methods:

{
	"cfgpath":"http://somewhere/path/to.cfg",
	"api":"http://somewhere/path/to/api.json",
	"auth":"eyzSomeKindOfOauthKeyForAuth",
	"noreplay": true,
	"ignoremethods": ["PUT", "PATCH"]
}


__RESPONSE FORMAT__


JSON scheme:

{
	"Info": {
		"Server": "somewhere/something",
		"Missed":{"someThing":4,"aValue":1}
	},
	"Conformant": [
		{
		"Method": "GET",
		"HTTPCode": 401,
		"Path": "/firstpath/orange",
		"Body": ""
		},
		{
		"Method": "POST",
		"HTTPCode": 500,
		"Path": "/secondpath/banana",
		"Body": "don't mind me"
		},
	],
	"Suspicious": [
		{
			"Method": "GET",
			"HTTPCode": 200,
			"Path": "/thirdpath/dubious/call",
			"Body": ""
		},
		{
			"Method": "POST",
			"HTTPCode": 200,
			"Path": "/fourthpath/account/update",
			"Body": "some kind of body"
		},
	]
}  

`
	// We only allow POST
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, usage)
		return
	}

	// Read POST body
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&opts)
	if err != nil && err != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Error:", err, "\n\n")
		fmt.Fprintln(w, usage)
		return
	}

	// Combinatorics
	if (opts.CfgPath == "" && opts.Cfg == "") || opts.API == "" || (opts.Auth == "" && !opts.NoAuth) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Error: all JSON fields are mandatory (cfg ⊻ cfgPath)\n\n")
		fmt.Fprintln(w, usage)
		return
	}

	// We _need_ a CFG
	if opts.Cfg != "" && opts.CfgPath != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Error: provide cfg ⊻ cfgPath\n\n")
		fmt.Fprintln(w, usage)
		return
	}

	/* Valid request format */

	// If we got a CfgPath, call out and read into response.Cfg
	var dbr io.Reader
	if opts.Cfg == "" {
		resp, err := http.Get(opts.CfgPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error: request for cfgPath failed → "+err.Error()+"\n\n")
			fmt.Fprintln(w, usage)
			return
		}
		// If we don't get a 200 OK
		if resp.StatusCode != 200 {
			w.WriteHeader(http.StatusBadRequest)
			buf, _ := ioutil.ReadAll(resp.Body)
			contents := string(buf)
			fmt.Fprint(w, "Error: request for cfgPath denied → "+contents+"\n\n")
			log.Println("fail: cfg request → ", contents)
			return
		}

		dbr = resp.Body

	} else {
		// Got full Cfg
		dbr = strings.NewReader(opts.Cfg)
	}

	// Load DB via cfg
	db, err := cfg.Load(dbr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "cfg load failed → "+err.Error()+"\n\n")
		fmt.Fprintln(w, usage)
		return
	}

	// Expose response.API URL to a io.Reader
	resp, err := http.Get(opts.API)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Error: request for API JSON failed → "+err.Error()+"\n\n")
		fmt.Fprintln(w, usage)
		return
	}
	// If we don't get a 200 OK
	if resp.StatusCode != 200 {
		w.WriteHeader(http.StatusBadRequest)
		buf, _ := ioutil.ReadAll(resp.Body)
		contents := string(buf)
		fmt.Fprint(w, "Error: request for API JSON denied → "+contents+"\n\n")
		log.Println("fail: api request → ", contents)
		return
	}

	// Load openapi spec
	api, err := openapi.Parse(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error: parsing OpenAPI specification failed → "+err.Error()+"\n\n")
		return
	}

	// Override target
	if opts.Target != "" {
		api.Servers = []openapi.Server{{URL: opts.Target}}
	}

	// Remove relevant methods from API signatures
	for _, method := range opts.IgnoreMethods {
		for _, methods := range api.Paths {

			down := strings.ToLower(method)
			delete(methods, down)
		}
	}

	// Insert auth to db
	if !opts.NoAuth {
		db.Records = append(db.Records, &cfg.Record{Tuples: []*cfg.Tuple{{Attributes: []*cfg.Attribute{{Name: "Authorization", Value: "Bearer " + opts.Auth}}}}})
	}
	db.BuildMap()

	// Invoke generator
	requests, missed, totalPossible, err := generate(api, db)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error: generation failed → "+err.Error()+"\n\n")
		fmt.Fprintln(w, usage)
		return
	}
	if requests == nil {
		requests = []*Request{}
	}

	// Return built requests if we don't want to replay
	if *&opts.NoReplay {
		enc := json.NewEncoder(w)
		err = enc.Encode([]interface{}{requests2strings(requests), missed, totalPossible})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error: response JSON encode failed → "+err.Error()+"\n\n")
			fmt.Fprintln(w, usage)
			return
		}
		return
	}

	// Optionally replay requests
	results := make(map[*Request]*Response)
	for _, request := range requests {
		resp := replay(request.Request, nil)
		results[request] = &resp
	}

	sus, ok, err := validate(results)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error: could not parse expected code → "+err.Error()+"\n\n")
		return
	}

	if opts.ADO {
		w.Header().Add("Content-Type", "text/plain")
		printADO(w, requests, missed, sus, ok)
		return
	}

	// Emit JSON by default for HTTP
	w.Header().Add("Content-Type", "application/json")
	err = printJSON(w, requests, missed, sus, ok)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error: could not marshal requests → "+err.Error()+"\n\n")
		return
	}
}

// Listen for HTTP requests
func listen(port, cert, key string) {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/generator", genHandler)

	var err error = nil
	if cert != key {
		// TLS
		emit("Listening on https://localhost" + port + " …")
		err = http.ListenAndServeTLS(port, cert, key, nil)
	} else {
		emit("Listening on http://localhost" + port + " …")
		err = http.ListenAndServe(port, nil)
	}
	if err != nil {
		fatal("err: listen failed →", err)
	}
}
