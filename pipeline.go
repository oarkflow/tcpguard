package tcpguard

type PipelineNode struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function string         `json:"function"`
	Params   map[string]any `json:"params,omitempty"`
}

type PipelineEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Pipeline struct {
	Nodes       []PipelineNode `json:"nodes"`
	Edges       []PipelineEdge `json:"edges"`
	Combination string         `json:"combination,omitempty"` // "AND" or "OR", defaults to "OR"
}

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
