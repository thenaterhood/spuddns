package system

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func stringSliceToReader(data []string) io.Reader {
	combined := strings.Join(data, "\n")
	combinedBytes := []byte(combined)

	return bytes.NewReader(combinedBytes)
}

func TestNameFullyQualifiedNames(t *testing.T) {
	type testCase struct {
		ndots          int
		name           string
		expected       bool
		searchDomain   []string
		fullyQualified []string
	}

	tests := []testCase{
		{
			ndots:          1,
			name:           "",
			expected:       false,
			searchDomain:   []string{},
			fullyQualified: []string{},
		},
		{
			ndots:          1,
			name:           "example",
			expected:       false,
			searchDomain:   []string{},
			fullyQualified: []string{"example."},
		},
		{
			ndots:          1,
			name:           "example.",
			expected:       false,
			searchDomain:   []string{"local", "lan"},
			fullyQualified: []string{"example.local.", "example.lan."},
		},
		{
			ndots:          1,
			name:           "example.com",
			expected:       true,
			searchDomain:   []string{"local"},
			fullyQualified: []string{"example.com.", "example.com.local."},
		},
		{
			ndots:          1,
			name:           "test.example.com.",
			expected:       true,
			searchDomain:   []string{},
			fullyQualified: []string{"test.example.com."},
		},
		{
			ndots:          2,
			name:           "example.com",
			expected:       false,
			searchDomain:   []string{"local", "lan"},
			fullyQualified: []string{"example.com.local.", "example.com.lan."},
		},
		{
			ndots:          2,
			name:           "example.com.",
			expected:       false,
			searchDomain:   []string{},
			fullyQualified: []string{"example.com."},
		},
		{
			ndots:          2,
			name:           "test.example.com.",
			expected:       true,
			searchDomain:   []string{"local"},
			fullyQualified: []string{"test.example.com.", "test.example.com.local."},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s / ndots = %d", test.name, test.ndots), func(t *testing.T) {
			resolvConf := ResolvConf{
				Options: map[string]string{"ndots": fmt.Sprintf("%d", test.ndots)},
				Search:  test.searchDomain,
			}

			isFullyQualifiedResult := resolvConf.NameIsFullyQualified(test.name)

			if isFullyQualifiedResult != test.expected {
				t.Errorf("wrong result for name is fully qualified, expected %v, got %v", test.expected, isFullyQualifiedResult)
			}

			fullyQualifiedNameResult := resolvConf.GetFullyQualifiedNames(test.name)
			if len(fullyQualifiedNameResult) != len(test.fullyQualified) {
				t.Errorf("wrong number of fully qualified names: actual = %v, expected = %v", fullyQualifiedNameResult, test.fullyQualified)
			}
			for _, expected := range test.fullyQualified {
				if !slices.Contains(fullyQualifiedNameResult, expected) {
					t.Errorf("missing fully qualified name %s in %v", expected, fullyQualifiedNameResult)
				}
			}

		})
	}
}

func TestSearchIsInName(t *testing.T) {
	type testCase struct {
		name         string
		expected     bool
		searchDomain []string
	}

	tests := []testCase{
		{
			name:         "",
			expected:     false,
			searchDomain: []string{},
		},
		{
			name:         "example.com.",
			expected:     false,
			searchDomain: []string{},
		},
		{
			name:         "example.com.local.",
			expected:     true,
			searchDomain: []string{"local."},
		},
		{
			name:         "example.local.com.",
			expected:     false,
			searchDomain: []string{"local."},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolvConf := ResolvConf{
				Search: test.searchDomain,
			}

			result := resolvConf.SearchDomainContains(test.name)
			if result != test.expected {
				t.Errorf("SearchDomainContains output: expected %v, actual %v", test.expected, result)
			}
		})
	}
}

func TestReadResolvConf(t *testing.T) {
	type testCase struct {
		name            string
		resolvConfLines []string
		expected        ResolvConf
		err             error
	}

	testCases := []testCase{
		{
			resolvConfLines: []string{},
			name:            "empty file",
			expected: ResolvConf{
				Options: map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{
				" ",
				"     ",
				"\t",
				"  ",
				"   ",
			},
			name: "whitespace file",
			expected: ResolvConf{
				Options: map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{
				"asdf",
				"     ",
				"\tasdfanameserver",
				"namser",
				"\t\n\b\t",
				"fasd",
				"searchasdf",
			},
			name: "garbage file",
			expected: ResolvConf{
				Options: map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"nameserver 1.1.1.1"},
			name:            "single nameserver",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1"},
				Options:     map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"nameserver"},
			name:            "malformed nameserver line",
			expected: ResolvConf{
				Nameservers: []string{},
				Options:     map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"nameserver", "nameserver 1.1.1.1"},
			name:            "malformed and valid nameserver lines",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1"},
				Options:     map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"nameserver 1.1.1.1", "nameserver 8.8.8.8", "nameserver 8.8.4.4"},
			name:            "multi nameserver",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1", "8.8.8.8", "8.8.4.4"},
				Options:     map[string]string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"search local"},
			name:            "single search",
			expected: ResolvConf{
				Nameservers: []string{},
				Options:     map[string]string{},
				Search:      []string{"local."},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"search "},
			name:            "malformed search",
			expected: ResolvConf{
				Nameservers: []string{},
				Options:     map[string]string{},
				Search:      []string{},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{"search local example"},
			name:            "multi search",
			expected: ResolvConf{
				Nameservers: []string{},
				Options:     map[string]string{},
				Search:      []string{"local.", "example."},
			},
			err: nil,
		},
		{
			resolvConfLines: []string{
				"search local example",
				"nameserver 1.1.1.1",
				"nameserver 8.8.8.8",
			},
			name: "multi search and multi nameservers",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1", "8.8.8.8"},
				Options:     map[string]string{},
				Search:      []string{"local.", "example."},
			},
		},
		{
			resolvConfLines: []string{
				"search local",
				"nameserver 1.1.1.1",
			},
			name: "single search and single nameserver",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1"},
				Options:     map[string]string{},
				Search:      []string{"local."},
			},
		},
		{
			resolvConfLines: []string{
				"search local example",
				"nameserver 1.1.1.1",
				"nameserver 8.8.8.8",
				"option ndots:4",
				"option attempts:2",
			},
			name: "search, ns, opts",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1", "8.8.8.8"},
				Options: map[string]string{
					"ndots":    "4",
					"attempts": "2",
				},
				Search: []string{"local.", "example."},
			},
		},
		{
			resolvConfLines: []string{
				"search local example",
				"nameserver 1.1.1.1",
				"nameserver 8.8.8.8",
				"option ndots:",
				"option attempts:2",
			},
			name: "malformed opt",
			expected: ResolvConf{
				Nameservers: []string{"1.1.1.1", "8.8.8.8"},
				Options: map[string]string{
					"attempts": "2",
				},
				Search: []string{"local.", "example."},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			result, err := newResolvConfFromReader(stringSliceToReader(test.resolvConfLines))

			if err != test.err {
				t.Errorf("unexpected or incorrect error parsing resolvconf, actual = %v, expected = %v", err, test.err)
			}

			if len(result.Nameservers) != len(test.expected.Nameservers) {
				t.Errorf("wrong number of nameservers: actual = %v, expected = %v", result.Nameservers, test.expected.Nameservers)
			}

			for _, ns := range test.expected.Nameservers {
				if !slices.Contains(result.Nameservers, ns) {
					t.Errorf("%v nameserver is missing from result = %v, expected = %v", ns, result.Nameservers, test.expected.Nameservers)
				}
			}

			if len(result.Search) != len(test.expected.Search) {
				t.Errorf("wrong number of search: actual = %v, expected = %v", result.Search, test.expected.Search)
			}

			for _, search := range test.expected.Search {
				if !slices.Contains(result.Search, search) {
					t.Errorf("%v search is missing from result = %v, expected = %v", search, result.Search, test.expected.Search)
				}
			}

			for opt, val := range test.expected.Options {
				actual, exists := result.Options[opt]

				if !exists {
					t.Errorf("key %s is missing from options", opt)
				}

				if actual != val {
					t.Errorf("wrong value for option %s, actual = %s, expected = %s", opt, actual, val)
				}
			}
		})
	}
}
