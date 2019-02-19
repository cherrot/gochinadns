package gochinadns

import (
	"strings"
)

type domainTrie struct {
	children map[string]*domainTrie
	end      bool
}

func (tr *domainTrie) Add(domain string) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}

	domain = strings.Trim(domain, ".")
	// "." contains all domains
	if domain == "" {
		tr.end = true
		tr.children = nil
		return
	}

	node := tr
	labels := strings.Split(domain, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		// domain is already contained in this trie.
		if node.end {
			return
		}

		if node.children == nil {
			node.children = make(map[string]*domainTrie)
		}
		label := labels[i]
		if node.children[label] == nil {
			node.children[label] = new(domainTrie)
		}
		node = node.children[label]
	}
	node.end = true
}

// google.com. contains mail.google.com
// play.google.com. DOES NOT contain mail.google.com
// domain MUST be a valid domain name.
func (tr *domainTrie) Contain(domain string) bool {
	if tr == nil {
		return false
	}
	labels := strings.Split(domain, ".")
	node := tr
	if node.end {
		return true
	}
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		node = node.children[label]
		if node == nil {
			return false
		}
		if node.end {
			return true
		}
	}
	// should not be here
	return false
}
