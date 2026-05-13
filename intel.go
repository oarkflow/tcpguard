package tcpguard

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oarkflow/condition"
)

type FileIntelFeed struct {
	Definition IntelDefinition
	BaseDir    string
}

type IndexedFileIntelFeed struct {
	Definition IntelDefinition
	BaseDir    string
	once       sync.Once
	loadErr    error
	exact      map[string]struct{}
	cidrs      []*net.IPNet
	globs      []string
}

func (f *IndexedFileIntelFeed) ID() string { return f.Definition.ID }

func (f *IndexedFileIntelFeed) Enrich(ctx context.Context, sec *Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.once.Do(func() { f.loadErr = f.load() })
	if f.loadErr != nil {
		return f.loadErr
	}
	matchValue := valueForPath(sec, f.Definition.Match)
	matched, matchType := f.match(matchValue)
	if !matched {
		return nil
	}
	if sec.Extra == nil {
		sec.Extra = condition.MapFacts{}
	}
	for key, value := range f.Definition.Fields {
		setFact(sec.Extra, key, value)
		setFact(sec.Facts, key, value)
		applyIntelField(sec, key, value)
	}
	applyIntelMetadata(sec, f.Definition.ID, f.Definition.Match, matchValue, matchType)
	return nil
}

func (f *IndexedFileIntelFeed) load() error {
	path := f.Definition.Path
	if f.BaseDir != "" && !filepath.IsAbs(path) {
		path = filepath.Join(f.BaseDir, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	f.exact = map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, network, err := net.ParseCIDR(line); err == nil {
			f.cidrs = append(f.cidrs, network)
			continue
		}
		if strings.Contains(line, "*") {
			f.globs = append(f.globs, line)
			continue
		}
		f.exact[line] = struct{}{}
	}
	return scanner.Err()
}

func (f *IndexedFileIntelFeed) match(value string) (bool, string) {
	if value == "" {
		return false, ""
	}
	if _, ok := f.exact[value]; ok {
		return true, "exact"
	}
	if ip := net.ParseIP(value); ip != nil {
		for _, network := range f.cidrs {
			if network.Contains(ip) {
				return true, "cidr"
			}
		}
	}
	for _, pattern := range f.globs {
		if glob(pattern, value) {
			return true, "pattern"
		}
	}
	return false, ""
}

func applyIntelField(sec *Context, key string, value any) {
	switch key {
	case "network.reputation", "network.ip.reputation":
		if n, ok := number(value); ok {
			sec.Network.Reputation = n
		}
	case "network.tor", "network.ip.tor":
		if b, ok := value.(bool); ok {
			sec.Network.Tor = b
		}
	case "network.ip.blacklisted":
		if b, ok := value.(bool); ok && b {
			setFact(sec.Facts, "threat.intel.source", "file")
		}
	}
}

func applyIntelMetadata(sec *Context, sourceID, matchPath, matchValue, matchType string) {
	if sec == nil {
		return
	}
	confidence := 0.7
	switch matchType {
	case "exact":
		confidence = 0.95
	case "cidr":
		confidence = 0.85
	case "pattern":
		confidence = 0.75
	}
	sec.Network.IntelSource = sourceID
	sec.Network.IntelMatchType = matchType
	sec.Network.IntelConfidence = confidence
	setContextFact(sec, "threat.intel.source", sourceID)
	setContextFact(sec, "threat.intel.match_path", matchPath)
	setContextFact(sec, "threat.intel.match_value", matchValue)
	setContextFact(sec, "threat.intel.match_type", matchType)
	setContextFact(sec, "threat.intel.confidence", confidence)
}

func (f FileIntelFeed) ID() string { return f.Definition.ID }

func (f FileIntelFeed) Enrich(ctx context.Context, sec *Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := f.Definition.Path
	path = renderString(path, sec, Decision{})
	if f.BaseDir != "" && !filepath.IsAbs(path) {
		path = filepath.Join(f.BaseDir, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	matchValue := valueForPath(sec, f.Definition.Match)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == matchValue || glob(line, matchValue) {
			if sec.Extra == nil {
				sec.Extra = condition.MapFacts{}
			}
			for key, value := range f.Definition.Fields {
				setFact(sec.Extra, key, value)
				setFact(sec.Facts, key, value)
				applyIntelField(sec, key, value)
			}
			matchType := "pattern"
			if line == matchValue {
				matchType = "exact"
			}
			applyIntelMetadata(sec, f.Definition.ID, f.Definition.Match, matchValue, matchType)
			return scanner.Err()
		}
	}
	return scanner.Err()
}
