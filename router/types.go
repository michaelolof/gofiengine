package router

import (
	"io"
	"net/http"

	"github.com/michaelolof/gofi/gofiengine/validators"
)

type HandlerFunc = func(c Context) error

type MiddlewareFunc = func(next HandlerFunc) HandlerFunc

type RouteOptions struct {
	// Provide additional information about your route
	Info Info
	// Define a reference to your Schema struct
	Schema any
	// Attach meta information to your route handlers that can be accessed in using the Context or Router interface
	Meta any
	// Register middleware functions for your route
	Middlewares []MiddlewareFunc
	// Define the handler for your route
	Handler func(c Context) error
}

type Info struct {
	// Prevent path from being documented
	Hidden       bool
	OperationId  string
	Summary      string
	Deprecated   bool
	Method       string
	Url          string
	Description  string
	ExternalDocs []ExternalDocs
}

type ExternalDocs struct {
	Url         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

type MetaMapInfo struct {
	Path      string
	Method    string
	MetaValue any
}

type RouterMeta interface {
	Route(path, method string) (any, bool)
	TryRoute(path, method string) any
	All() map[string]map[string]any
	Filter(fn func(path, method string) bool) map[string]map[string]any
	FilterAsSlice(fn func(path, method string) bool) []MetaMapInfo
}

type InjectOptions struct {
	Path    string
	Method  string
	Query   map[string]string
	Paths   map[string]string
	Headers map[string]string
	Cookies []http.Cookie
	Body    io.Reader
	Handler *RouteOptions
}

type CustomSchemaProps struct {
	// Add a custom decoder. Will defer to the json.Decoder if not passed. It is advised to use the json Unmarshal method. Prefer this if you don't have access to the custom type
	Decoder func(val any) (any, error) `json:"-"`
	// Add a custom encoder. Will defer to the json.Encode if not passed. It is advised to use the json Marshal method. Prefer this if you don't have access to the custom type
	Encoder func(val any) (string, error) `json:"-"`
	// Define the openapi3 type for your custom type E.g "string", "integer", "number", 'boolean", "array" etc
	Type string `json:"type,omitempty"`
	// Define the openapi3 type for your custom type E.g "date", "date-time", "int32", 'int64", "uuie" etc
	Format string `json:"format,omitempty"`
}

type ValidatorContext = validators.ValidatorContext
type ValidatorOption = validators.ValidatorArg
