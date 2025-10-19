package tcpguard

// InMemoryPipelineFunctionRegistry implements PipelineFunctionRegistry
type InMemoryPipelineFunctionRegistry struct {
	functions map[string]func(ctx *Context) any
}

func NewInMemoryPipelineFunctionRegistry() *InMemoryPipelineFunctionRegistry {
	return &InMemoryPipelineFunctionRegistry{
		functions: make(map[string]func(ctx *Context) any),
	}
}

func (r *InMemoryPipelineFunctionRegistry) Register(name string, fn func(ctx *Context) any) {
	r.functions[name] = fn
}

func (r *InMemoryPipelineFunctionRegistry) Get(name string) (func(ctx *Context) any, bool) {
	fn, exists := r.functions[name]
	return fn, exists
}
