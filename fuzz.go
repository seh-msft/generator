// Copyright (c) 2021, Microsoft Corporation, Sean Hinchee
// Licensed under the MIT License.

package main

import (
	"crypto/rand"
	"math/big"

	"github.com/seh-msft/openapi"
)

// Generate a more random property body
func randProperty(obj map[string]string, name string, property openapi.Property) map[string]string {
	switch property.Type {
	case "string":
		switch property.Format {
		case "date-time":
			obj[name] = "00-00-0000"
		}

		if len(property.Enums) > 0 {
			// Select an enum at random
			i, err := rand.Int(rand.Reader, big.NewInt(int64(len(property.Enums))))
			if err != nil {
				fatal("err: could not use rand →", err)
			}

			obj[name] = property.Enums[int(i.Int64())]

		} else {
			obj[name] = "\"\""
		}

	case "array":
		obj[name] = "[]"

	case "integer":
		// Format
		obj[name] = "0"
		switch property.Format {
		case "int32":
		default:
		}

	default:
		obj[name] = `""`
	}

	return obj
}
