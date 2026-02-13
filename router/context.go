package router

import "net/http"

type Context interface {
	// Returns the http writer instance for the request
	Writer() http.ResponseWriter
	// Returns the http request instance for the request
	Request() *http.Request
	// Access global store defined on the server router instance
	GlobalStore() ReadOnlyStore
	// Access route context data store. Useful for passing and retrieving during a request lifetime
	DataStore() GofiStore
	// Access static meta information defined on the route
	Meta() ContextMeta
	// Sends a schema response object for the given status code
	Send(code int, obj any) error

	GetSchemaRules(pattern, method string) any
}

type ReadOnlyStore interface {
	// Checks whether a value exists in the global store
	Has(key string) bool
	// Returns the value set in the global store using the key passed. Returns false if the value isn't found
	Get(key string) (any, bool)
	// Returns the value set in the global store using the key passed. Panics if the value isn't found
	TryGet(key string) any
}

type GofiStore interface {
	ReadOnlyStore
	// Sets a value to the global store
	Set(key string, val any)
}

type ContextMeta interface {
	This() (any, bool)
}
