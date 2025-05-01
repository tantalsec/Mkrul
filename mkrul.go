package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unicode"
)

const (
	VERSION = 4
)

const (
	CTX = 1
	KEY = 2
	VAL = 3
	DEPTH = 4
)

const (
	NUMERIC = 1
	STRING  = 2
	REGEXP  = 3
)

const (
	BLOCK = 1
	PASS  = 2
	EQ    = 3
	NEQ   = 4
)

const (
	AUTH_HEADER= 11
	HEADERS    = 4
	URLENC     = 3
	BASE64     = 9
	BASE64_URL = 10
	COOKIE     = 8
	JSON       = 5
	JSON_OBJ   = 6
	JSON_ARRAY = 7
	PATH       = 2
	HTTP       = 1
	JWT        = 12
)

type Endpoint struct {
	Method string `json:"method"`
	Path  string   `json:"path"`
	Rules []string `json:"rules"`
}

type Stmt struct {
	Var    uint8
	Op     uint8
	Val    string
	Regexp string
}

type Sentinel struct {
	Method string
	Path  []string
	Rules [][][]Stmt
}

type NopWriter uint64

func (w *NopWriter) Write(data []byte) (int, error) {
	*w += NopWriter(len(data))
	return len(data), nil
}

func (w *NopWriter) Offset() uint64 {
	return uint64(*w)
}

func parseVar(val string) (uint8, error) {
	switch val {
	case "$ctx":
		return CTX, nil
	case "$key":
		return KEY, nil
	case "$val":
		return VAL, nil
	case "$depth":
		return DEPTH, nil
	}
	return 0, fmt.Errorf("unknown variable: %s", val)
}

func parseOp(val string) (uint8, error) {
	switch val {
	case "block":
		return BLOCK, nil
	case "pass":
		return PASS, nil
	case "==":
		return EQ, nil
	case "!=":
		return NEQ, nil
	}
	return 0, fmt.Errorf("unknown operator: %s", val)
}

func parseRule(rule string) ([][]Stmt, error) {
	var result [][]Stmt

	groups := scanGroups(rule)

	for _, group := range groups {
		stmt, err := parseGroup(group)

		if err != nil {
			return nil, err
		}

		result = append(result, stmt)
	}

	return result, nil
}

func scanWord(dst *strings.Builder, src *bytes.Buffer) {
	for {
		r, _, err := src.ReadRune()

		if err != nil { // EOF
			return
		}

		if unicode.IsSpace(r) {
			return
		}

		dst.WriteRune(r)
	}
}

func scanDelim(dst *strings.Builder, src *bytes.Buffer, delim rune) {
	escape := false

	for {
		r, _, err := src.ReadRune()

		if err != nil {
			log.Fatalln("invalid string")
		}

		if escape {
			dst.WriteRune(r)
			escape = false
		} else if r == '\\' {
			escape = true
		} else if r == delim {
			dst.WriteRune(r)
			return
		} else {
			dst.WriteRune(r)
		}
	}
}

func scanGroups(text string) [][]string {
	var result [][]string
	var group []string
	var sb strings.Builder

	buf := bytes.NewBufferString(text)

	for {
		r, _, err := buf.ReadRune()

		if err != nil { // EOF
			break
		}

		if unicode.IsSpace(r) {
			continue
		}

		switch r {
		case ':':
			result = append(result, group)
			group = nil
		case '\'':
			sb.WriteRune(r)
			scanDelim(&sb, buf, '\'')
			group = append(group, sb.String())
			sb.Reset()
		case '/':
			sb.WriteRune(r)
			scanDelim(&sb, buf, '/')
			group = append(group, sb.String())
			sb.Reset()
		default:
			sb.WriteRune(r)
			scanWord(&sb, buf)
			group = append(group, sb.String())
			sb.Reset()
		}
	}

	if len(group) != 0 {
		result = append(result, group)
	}

	return result
}

func parseGroup(tokens []string) ([]Stmt, error) {
	var result []Stmt
	var curr Stmt
	var err error

	for _, token := range tokens {
		if strings.HasPrefix(token, "'") {
			curr.Val = strings.Trim(token, "'")
		} else if strings.HasPrefix(token, "/") {
			curr.Regexp = token
		} else if strings.HasPrefix(token, "$") {
			curr.Var, err = parseVar(token)

			if err != nil {
				return nil, err
			}
		} else {
			curr.Op, err = parseOp(token)

			if err != nil {
				return nil, err
			}
		}

		if (curr.Var != 0 && curr.Op != 0 && (len(curr.Val) != 0 || len(curr.Regexp) != 0)) || (curr.Op == BLOCK || curr.Op == PASS) {
			result = append(result, curr)
			curr = Stmt{}
		}
	}

	return result, nil
}

func readEndpoints(path string) ([]Endpoint, error) {
	var err error
	var file *os.File
	var result []Endpoint

	if file, err = os.Open(path); err != nil {
		return nil, err
	}

	defer file.Close()

	dec := json.NewDecoder(file)
	err = dec.Decode(&result)

	if err != nil && err != io.EOF {
		return nil, err
	}

	return result, nil
}

func makeSentinels(endpoints []Endpoint) ([]Sentinel, error) {
	var result []Sentinel

	for _, endpoint := range endpoints {
		var sentinel Sentinel

		sentinel.Method = endpoint.Method

		for _, val := range strings.Split(endpoint.Path, "/") {
			if len(val) == 0 {
				continue
			}

			sentinel.Path = append(sentinel.Path, val)
		}

		for _, val := range endpoint.Rules {
			rule, err := parseRule(val)

			if err != nil {
				return nil, err
			}

			sentinel.Rules = append(sentinel.Rules, rule)
		}

		result = append(result, sentinel)
	}

	return result, nil
}

func offsetTable(snts []Sentinel) ([]uint64, error) {
	var err error
	var w NopWriter
	var result []uint64

	_ = binary.Write(&w, binary.LittleEndian, uint32(0))
	_ = binary.Write(&w, binary.LittleEndian, uint16(len(snts)))

	for i := 0; i < len(snts); i++ {
		_ = binary.Write(&w, binary.LittleEndian, uint64(0))
	}

	_ = binary.Write(&w, binary.LittleEndian, uint16(len(snts)))

	for _, snt := range snts {
		result = append(result, w.Offset())
		if err = writeSentinel(&w, snt); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func writeSentinels(path string, snts []Sentinel) error {
	var err error
	var w *os.File
	var offs []uint64

	w, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0655)

	if err != nil {
		return err
	}

	defer w.Close()

	err = binary.Write(w, binary.LittleEndian, uint32(VERSION)) // version

	if err != nil {
		return err
	}

	offs, err = offsetTable(snts)

	if err != nil {
		return err
	}

	err = writeUint16(w, uint16(len(offs)))

	if err != nil {
		return err
	}

	for _, off := range offs {
		if err = writeUint64(w, off); err != nil {
			return err
		}
	}

	err = writeUint16(w, uint16(len(snts)))

	if err != nil {
		return err
	}

	for _, snt := range snts {
		if err = writeSentinel(w, snt); err != nil {
			return err
		}
	}

	return nil
}

func writeStr(w io.Writer, val string) error {
	var err error

	err = binary.Write(w, binary.LittleEndian, uint16(len(val)))

	if err != nil {
		return err
	}

	_, err = w.Write([]byte(val))

	return err
}

func writeUint64(w io.Writer, val uint64) error {
	return binary.Write(w, binary.LittleEndian, val)
}

func writeUint16(w io.Writer, val uint16) error {
	return binary.Write(w, binary.LittleEndian, val)
}

func writeUint8(w io.Writer, val uint8) error {
	return binary.Write(w, binary.LittleEndian, val)
}

func getCtxCode(val string) (uint8, error) {
	var n uint8

	switch val {
	case "headers":
		n = HEADERS
	case "urlenc":
		n = URLENC
	case "base64":
		n = BASE64
	case "cookie":
		n = COOKIE
	case "json":
		n = JSON
	case "json_obj":
		n = JSON_OBJ
	case "json_array":
		n = JSON_ARRAY
	case "path":
		n = PATH
	case "http":
		n = HTTP
	case "auth_header":
		n = AUTH_HEADER
	case "base64_url":
		n = BASE64_URL
	case "jwt":
		n = JWT
	default:
		return 0, fmt.Errorf("unknown context: %s", val)
	}
	return n, nil
}

func writeCtx(w io.Writer, val string) error {
	var r uint64 = 0

	contexts := strings.Split(val, "|")

	for _, c := range contexts {
		ctx := strings.TrimSpace(c)
		n, err := getCtxCode(ctx)
		if err != nil {
			return err
		}
		r |= (1 << n)
	}

	return writeUint64(w, r)
}

func writeSentinel(w io.Writer, snt Sentinel) error {
	var err error

	if err = writeStr(w, snt.Method); err != nil {
		return err
	}

	if err = writeUint16(w, uint16(len(snt.Path))); err != nil {
		return err
	}

	for _, val := range snt.Path {
		if err = writeStr(w, val); err != nil {
			return err
		}
	}

	if err = writeUint16(w, uint16(len(snt.Rules))); err != nil {
		return err
	}

	for _, groups := range snt.Rules {
		if err = writeUint16(w, uint16(len(groups))); err != nil {
			return err
		}

		for _, stmts := range groups {
			if err = writeUint16(w, uint16(len(stmts))); err != nil {
				return err
			}

			for _, stmt := range stmts {
				if err = writeUint8(w, stmt.Var); err != nil {
					return err
				}

				if err = writeUint8(w, stmt.Op); err != nil {
					return err
				}

				if stmt.Var == CTX {
					if err = writeUint8(w, NUMERIC); err != nil {
						return err
					}

					if err = writeCtx(w, stmt.Val); err != nil {
						return err
					}
				} else if len(stmt.Regexp) != 0 {
					if err = writeUint8(w, REGEXP); err != nil {
						return err
					}

					if err = writeStr(w, stmt.Regexp); err != nil {
						return err
					}
				} else {
					if err = writeUint8(w, STRING); err != nil {
						return err
					}

					if err = writeStr(w, stmt.Val); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

var input = flag.String("i", "endpoints.json", "endpoints configuration")
var output = flag.String("o", "sentinels.bin", "waf sentinels binary data")
var debug = flag.Bool("d", false, "debug mode")

func main() {
	var err error
	var epts []Endpoint
	var snts []Sentinel

	flag.Parse()

	epts, err = readEndpoints(*input)

	if err != nil {
		log.Fatalln(err)
	}

	if *debug {
		fmt.Printf("endpoints: %+v\n", epts)
	}

	snts, err = makeSentinels(epts)

	if err != nil {
		log.Fatalln(err)
	}

	if *debug {
		fmt.Printf("sentinels: %+v\n", snts)
	}

	err = writeSentinels(*output, snts)

	if err != nil {
		log.Fatalln(err)
	}
}
