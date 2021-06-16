// Copyright (c) 2021, Microsoft Corporation, Sean Hinchee
// Licensed under the MIT License.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"

	"github.com/seh-msft/cfg"
)

// In should be a _complete_ HTTP request
// Out is optional and a JSON form of the response will be written if non-nil
func replay(req *http.Request, out io.Writer) Response {
	req.RequestURI = ""
	req.URL.Scheme = *proto
	req.URL.Host = req.Host

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fatal("err: could not make request →", err)
	}

	http2response := func(r http.Response) Response {
		resp := Response{
			Status:           r.Status,
			StatusCode:       r.StatusCode,
			Proto:            r.Proto,
			ProtoMajor:       r.ProtoMajor,
			ProtoMinor:       r.ProtoMinor,
			Header:           r.Header,
			ContentLength:    r.ContentLength,
			TransferEncoding: r.TransferEncoding,
			Close:            r.Close,
			Uncompressed:     r.Uncompressed,
		}

		/* TODO - we may want to be able to check a global options table?
		// Do we want REST/flag options for these?
		if !*noBody {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			body := buf.String()
			resp.Body = body
		}

		if *yesTLS {
			resp.TLS = r.TLS
		}
		*/

		return resp
	}

	if out != nil {
		w := bufio.NewWriter(out)
		r := http2response(*resp)
		enc := json.NewEncoder(w)
		err := enc.Encode(r)
		if err != nil {
			fatal("err: could not encode response to JSON →", err)
		}
		w.Flush()
		return r
	}

	return http2response(*resp)
}

// Validate against API spec
func validate(results map[*Request]*Response) ([]Set, []Set, error) {
	var sus []Set
	var ok []Set

	// If replayed, compare results to specification
	for request, response := range results {
		// Responses ⇒ ["200"]"some kind of reason"
		for expected := range request.Method.Responses {
			eint, err := strconv.Atoi(expected)
			if err != nil {
				return nil, nil, err
			}

			// Check expected vs reality
			// If we get an expected result, this may be a permission violation
			// TODO - options/modes for what qualifies as a permission violation
			// For now, employ a heuristic
			if eint == response.StatusCode {
				// Status code matches a known response
				sus = append(sus, Set{request, response})
			} else {
				// We don't expect the response received
				// TODO - better detection heuristics/options for abnormal responses
				ok = append(ok, Set{request, response})
			}
		}
	}

	return sus, ok, nil
}

// JSON-formatted output
func printJSON(w io.Writer, requests []*Request, missed map[string]uint64, sus, ok []Set) error {
	type Group struct {
		Method   string
		HTTPCode int
		Path     string
		Body     string
	}
	type Output struct {
		Info struct {
			// TODO - account for multiple servers, make this part of Request{} ?
			Server string
			Missed map[string]uint64
		}
		Conformant []Group
		Suspicious []Group
	}
	var out Output
	out.Info.Server = requests[0].Host
	out.Info.Missed = missed

	for _, set := range ok {
		out.Conformant = append(out.Conformant, Group{
			Method:   set.Request.Request.Method,
			HTTPCode: set.Response.StatusCode,
			Path:     set.Request.URL.Path,
			Body:     set.Response.Body,
		})
	}

	for _, set := range sus {
		out.Suspicious = append(out.Suspicious, Group{
			Method:   set.Request.Request.Method,
			HTTPCode: set.Response.StatusCode,
			Path:     set.Request.URL.Path,
			Body:     set.Response.Body,
		})
	}

	enc := json.NewEncoder(w)
	return enc.Encode(out)
}

// ADO-formatted output with debug/warnings/errors
func printADO(w io.Writer, requests []*Request, missed map[string]uint64, sus, ok []Set) {
	// Misc debug info
	fmt.Fprintf(w, "##[group]Miscellaneous Info\n")
	// TODO - account for multiple servers, make this part of Request{} ?
	fmt.Fprintf(w, "##[debug]Server we're targeting: `%s`\n", requests[0].Host)
	fmt.Fprintf(w, "##[debug]Parameters we missed:\n")
	for param, count := range missed {
		fmt.Fprintf(w, "##[debug]`%s` missed %d times\n", param, count)
	}
	fmt.Fprintf(w, "##[endgroup]\n\n")

	// Log 'ok' requests
	if len(ok) > 0 {
		fmt.Fprintf(w, "##[group]Conformant (ok) Responses (%d requests total)\n", len(ok))
		for _, set := range ok {
			fmt.Fprintf(w, "##[debug]Conformant Response code `HTTP %d` for path `HTTP %s` `%s`\n", set.Response.StatusCode, strings.ToUpper(set.Request.Request.Method), set.Request.URL.Path)
			if len(set.Response.Body) > 0 {
				fmt.Fprintf(w, "##[debug]Body received:\n\n```\n%s\n```\n", set.Response.Body)
			}
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "##[endgroup]\n\n")
	}

	// TODO - error on strict mode for ADO?
	// For every suspicious request, drop a warning
	if len(sus) > 0 {
		fmt.Fprintf(w, "##vso[task.logissue type=warning]Suspicious (bad) Responses (%d requests total)\n", len(sus))
		for _, bad := range sus {
			fmt.Fprintf(w, "##vso[task.logissue type=warning]Suspicious Response code `HTTP %d` for path `HTTP %s` `%s`\n", bad.Response.StatusCode, strings.ToUpper(bad.Request.Request.Method), bad.Request.URL.Path)
			if len(bad.Response.Body) > 0 {
				fmt.Fprintf(w, "##[debug]Body received:\n\n```\n%s\n```\n", bad.Response.Body)
			}
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "##[endgroup]\n\n")
	}
}

// Ingest a db file
// Form of `someId=abc-123-098-def` one per line
func ingestDb(name string) cfg.Cfg {
	file, err := os.Open(name)
	if err != nil {
		fatal(`err: could not open db file "`, name, `" →`, err)
	}

	config, err := cfg.Load(file)
	if err != nil {
		fatal("err: cfg could not load →", err)
	}

	return config
}

// Fatal - end program with an error message and newline
func fatal(s ...interface{}) {
	fmt.Fprintln(os.Stderr, s...)
	os.Exit(1)
}

// Pretty logging of HTTP requests
func prettyRequest(r *http.Request) string {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		return ""
	}

	return string(dump)
}

// Chatty emission
func chat(s ...interface{}) {
	if !*chatty {
		return
	}

	emit(s...)
}

// Stderr emission
func emit(s ...interface{}) {
	fmt.Fprintln(stderr, s...)
	stderr.Flush()
}
