package snooze

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

const (
	mime_json     = "application/json"
	mime_xml      = "application/xml"
	mime_text_xml = "text/xml"

	hdr_content_type = "Content-Type"
)

type Client struct {
	Doer        Doer
	Before      func(*http.Request)
	HandleError func(*ErrorResponse) error
	Root        string
}

// Doer executes http requests.  It is implemented by *http.Client.  You can
// wrap *http.Client with layers of Doers to form a stack of client-side
// middleware.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ErrorResponse struct {
	Status              string
	StatusCode          int
	ResponseBody        []byte
	ResponseContentType string
}

func (e ErrorResponse) Error() string {
	return fmt.Sprintf("%s [%s]", e.Status, e.ResponseContentType)
}

type resultInfo struct {
	errorIndex          int
	payloadIndex        int
	payloadType         reflect.Type
	resultLength        int
	responseContentType string
}

func (info *resultInfo) result(err error, bytes []byte) []reflect.Value {
	result := make([]reflect.Value, info.resultLength)
	if info.errorIndex > -1 {
		if err != nil {
			result[info.errorIndex] = reflect.ValueOf(&err).Elem()
		} else {
			result[info.errorIndex] = nilError
		}
	}
	if info.payloadIndex > -1 {
		if bytes != nil {
			target := reflect.New(info.payloadType)

			switch info.payloadType.Name() {
			case "string":
				contents := string(bytes)
				result[info.payloadIndex] = reflect.ValueOf(contents)

			default:
				respContentType := info.responseContentType
				if respContentType != "" {
					if strings.Contains(respContentType, ";") {
						// strip any extra detail
						respContentType = respContentType[:strings.Index(respContentType, ";")]
					}
				} else {
					respContentType = mime_json
				}
				switch respContentType {
				case mime_json:
					err = json.Unmarshal(bytes, target.Interface())
				case mime_xml:
					fallthrough
				case mime_text_xml:
					err = xml.Unmarshal(bytes, target.Interface())
				default:
					fmt.Printf("\nContent Type (%s) not supported by snooze.\n", respContentType)
				}

				if err != nil {
					return info.result(err, nil)
				}
				result[info.payloadIndex] = target.Elem()
			}

		} else {
			result[info.payloadIndex] = reflect.Zero(info.payloadType)
		}
	}
	return result
}

var nilError = reflect.Zero(reflect.TypeOf((*error)(nil)).Elem())

func (c *Client) Create(in interface{}) {
	inputValue := reflect.ValueOf(in).Elem()
	inputType := inputValue.Type()
	for i := 0; i < inputValue.NumField(); i++ {
		fieldStruct := inputType.Field(i)
		fieldType := fieldStruct.Type

		info := &resultInfo{
			resultLength: fieldType.NumOut(),
			errorIndex:   -1,
			payloadIndex: -1,
		}

		wrapper := &requestWrapper{
			client:       c,
			info:         info,
			originalPath: fieldStruct.Tag.Get("path"),
		}

		if method, ok := fieldStruct.Tag.Lookup("method"); ok {
			wrapper.method = method
		} else {
			method = http.MethodGet
		}

		if contentType, ok := fieldStruct.Tag.Lookup("contentType"); ok {
			wrapper.contentType = contentType
		} else {
			wrapper.contentType = mime_json
		}

		for n := 0; n < info.resultLength; n++ {
			out := fieldType.Out(n)
			if out == reflect.TypeOf((*error)(nil)).Elem() {
				info.errorIndex = n
			} else {
				info.payloadIndex = n
				info.payloadType = out
			}
		}

		fieldValue := inputValue.Field(i)
		fieldValue.Set(reflect.MakeFunc(fieldType, wrapper.execute))
	}
}

func (r *requestWrapper) execute(args []reflect.Value) []reflect.Value {
	// Prepare Request Parameters
	path := r.originalPath
	var body interface{}
	for n, av := range args {
		if av.Kind() == reflect.Struct || av.Kind() == reflect.Ptr {
			body = av.Interface()
			continue
		}
		path = strings.Replace(path, fmt.Sprintf("{%v}", n), url.QueryEscape(fmt.Sprint(av.Interface())), -1)
	}

	// Prepare Request Body
	var err error
	buffer := make([]byte, 0)
	if r.method != http.MethodGet && body != nil {

		switch r.contentType {
		case mime_json:
			buffer, err = json.Marshal(body)
		case mime_xml:
			buffer, err = xml.Marshal(body)
		default:
			return r.info.result(fmt.Errorf("ContentType (%s) not supported.", r.contentType), nil)
		}
		if err != nil {
			return r.info.result(err, nil)
		}
	}

	// Prepare Request
	req, err := http.NewRequest(r.method, r.client.Root+path, bytes.NewBuffer(buffer))
	if err != nil {
		return r.info.result(err, nil)
	}
	req.Header.Set(hdr_content_type, r.contentType)
	client := r.client.Doer
	if client == nil {
		client = new(http.Client)
	}
	if r.client.Before != nil {
		r.client.Before(req)
	}

	// Send Request
	resp, err := r.client.Doer.Do(req)
	if err != nil {
		return r.info.result(err, nil)
	}

	// Process Response
	r.info.responseContentType = resp.Header.Get(hdr_content_type)
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r.info.result(err, nil)
	}
	if isErrorResponse(resp) {
		apiErr := ErrorResponse{
			Status:              resp.Status,
			StatusCode:          resp.StatusCode,
			ResponseBody:        bytes,
			ResponseContentType: r.info.responseContentType,
		}
		var handled error
		if r.client.HandleError != nil {
			handled = r.client.HandleError(&apiErr)
		} else {
			handled = apiErr
		}

		return r.info.result(handled, nil)
	} else {
		return r.info.result(nil, bytes)
	}
}

type requestWrapper struct {
	originalPath,
	method,
	contentType string
	client *Client
	info   *resultInfo
}

func isErrorResponse(r *http.Response) bool {
	if r.StatusCode > 399 {
		return true
	}

	return false
}
