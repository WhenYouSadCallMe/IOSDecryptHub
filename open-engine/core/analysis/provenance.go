package analysis

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var (
	ErrValueNotFound = errors.New("provenance value not found")
	ErrInvalidEdge   = errors.New("provenance edge is invalid")
)

type ValueNode struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Hash        string `json:"hash,omitempty"`
	Length      int    `json:"length,omitempty"`
	DataType    string `json:"dataType,omitempty"`
	Sensitivity string `json:"sensitivity,omitempty"`
}

type Edge struct {
	From       string  `json:"from"`
	To         string  `json:"to"`
	Operation  string  `json:"operation"`
	EventID    string  `json:"eventId,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type Direction string

const (
	DirectionForward  Direction = "forward"
	DirectionBackward Direction = "backward"
)

type TraceStep struct {
	Value ValueNode `json:"value"`
	Via   *Edge     `json:"via,omitempty"`
}

type Graph struct {
	mu     sync.RWMutex
	values map[string]ValueNode
	edges  []Edge
}

func NewGraph() *Graph {
	return &Graph{values: make(map[string]ValueNode)}
}

func (g *Graph) UpsertValue(value ValueNode) (string, error) {
	if strings.TrimSpace(value.ID) == "" {
		if strings.TrimSpace(value.Hash) == "" {
			return "", fmt.Errorf("%w: value id or hash is required", ErrValueNotFound)
		}
		value.ID = "value:" + strings.TrimSpace(value.Hash)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, ok := g.values[value.ID]; ok {
		if value.Name == "" {
			value.Name = existing.Name
		}
		if value.Hash == "" {
			value.Hash = existing.Hash
		}
	}
	g.values[value.ID] = value
	return value.ID, nil
}

func (g *Graph) Link(edge Edge) error {
	if strings.TrimSpace(edge.From) == "" || strings.TrimSpace(edge.To) == "" || strings.TrimSpace(edge.Operation) == "" {
		return ErrInvalidEdge
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.values[edge.From]; !ok {
		return fmt.Errorf("%w: from=%s", ErrValueNotFound, edge.From)
	}
	if _, ok := g.values[edge.To]; !ok {
		return fmt.Errorf("%w: to=%s", ErrValueNotFound, edge.To)
	}
	g.edges = append(g.edges, edge)
	return nil
}

func (g *Graph) Values() []ValueNode {
	g.mu.RLock()
	values := make([]ValueNode, 0, len(g.values))
	for _, value := range g.values {
		values = append(values, value)
	}
	g.mu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func (g *Graph) Edges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]Edge(nil), g.edges...)
}

func (g *Graph) Trace(start string, direction Direction, maxDepth int) ([]TraceStep, error) {
	if maxDepth < 1 {
		maxDepth = 32
	}
	g.mu.RLock()
	if _, ok := g.values[start]; !ok {
		g.mu.RUnlock()
		return nil, fmt.Errorf("%w: %s", ErrValueNotFound, start)
	}
	values := make(map[string]ValueNode, len(g.values))
	for id, value := range g.values {
		values[id] = value
	}
	edges := append([]Edge(nil), g.edges...)
	g.mu.RUnlock()

	type queueItem struct {
		id    string
		depth int
		via   *Edge
	}
	queue := []queueItem{{id: start}}
	visited := map[string]bool{start: true}
	result := make([]TraceStep, 0)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		via := item.via
		result = append(result, TraceStep{Value: values[item.id], Via: via})
		if item.depth >= maxDepth {
			continue
		}
		for i := range edges {
			edge := edges[i]
			var next string
			switch direction {
			case DirectionBackward:
				if edge.To != item.id {
					continue
				}
				next = edge.From
			default:
				if edge.From != item.id {
					continue
				}
				next = edge.To
			}
			if visited[next] {
				continue
			}
			visited[next] = true
			copyEdge := edge
			queue = append(queue, queueItem{id: next, depth: item.depth + 1, via: &copyEdge})
		}
	}
	return result, nil
}
