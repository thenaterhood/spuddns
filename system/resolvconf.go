package system

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const ndotsOpt = "ndots"

type ResolvConf struct {
	Search       []string
	Nameservers  []string
	Options      map[string]string
	path         string
	lastModified time.Time
	// sortlist is intentionally excluded for now
}

func (r *ResolvConf) Watch() {
	go func() {
		for {
			fileStats, err := os.Stat(r.path)
			if err != nil {
				continue
			}

			if fileStats.ModTime().After(r.lastModified) {
				newResolvConf, err := NewResolvConfFromPath(r.path)
				if err != nil {
					continue
				}

				r.Search = newResolvConf.Search
				r.Nameservers = newResolvConf.Nameservers
				r.Options = newResolvConf.Options
				r.path = newResolvConf.path
				r.lastModified = newResolvConf.lastModified
			}

			time.Sleep(5 * time.Second)
		}
	}()
}

func (r *ResolvConf) NameIsFullyQualified(name string) bool {

	if name == "" {
		return false
	}

	ndots := 1
	ndotsStr, optExists := r.Options[ndotsOpt]
	if optExists {
		ndotsInt, err := strconv.Atoi(ndotsStr)
		if err == nil {
			ndots = ndotsInt
		}
	}

	actualDot := 0

	// Intentionally dropping the final "." as the dns
	// library requires it, so that we can save ourselves
	// some work if we're queried for a bare name like "example."
	for _, ch := range name[:len(name)-1] {
		if ch == '.' {
			actualDot++
			if actualDot >= ndots {
				return true
			}
		}
	}

	return false
}

func (r *ResolvConf) GetFullyQualifiedNames(name string) []string {
	names := []string{}

	if name == "" {
		return names
	}

	name = makeQualified(name)

	if r.NameIsFullyQualified(name) || len(r.Search) < 1 {
		names = append(names, name)
	}

	for _, search := range r.Search {
		if strings.HasSuffix(name, search) {
			continue
		}
		names = append(names, makeQualified(name+search))
	}

	return names
}

func (r *ResolvConf) SearchDomainContains(name string) bool {
	if name == "" {
		return false
	}

	name = makeQualified(name)

	for _, search := range r.Search {
		idx := strings.Index(name, search)

		if idx > 0 && name[idx:] == search {
			return true
		}
	}

	return false
}

func newResolvConfFromReader(reader io.Reader) (*ResolvConf, error) {
	resolvConf := ResolvConf{
		Options: map[string]string{},
	}
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		words := strings.Fields(scanner.Text())

		if len(words) < 2 {
			continue
		}

		switch words[0] {
		case "nameserver":
			resolvConf.Nameservers = append(resolvConf.Nameservers, words[1])
		case "search":
			for _, s := range words[1:] {
				resolvConf.Search = append(resolvConf.Search, makeQualified(s))
			}
		case "option":
			option := strings.Split(words[1], ":")
			if len(option) < 2 {
				continue
			}
			resolvConf.Options[option[0]] = option[1]
		case "sortlist":
		default:
		}
	}

	return &resolvConf, nil
}

func makeQualified(name string) string {
	if len(name) < 1 {
		return "."
	}

	if name[len(name)-1] != '.' {
		return name + "."
	}

	return name
}

func NewResolvConfFromPath(path string) (*ResolvConf, error) {

	conf, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer conf.Close()

	resolvConf, err := newResolvConfFromReader(conf)
	if err != nil {
		return resolvConf, err
	}

	if stat, _ := conf.Stat(); stat != nil {
		resolvConf.lastModified = stat.ModTime()
	}

	resolvConf.path = path

	return resolvConf, nil
}
