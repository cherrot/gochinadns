package gochinadns

import (
	"reflect"
	"testing"
)

func TestTrieNormalize(t *testing.T) {
	trie := new(domainTrie)
	trie.Add("")
	if trie.end || trie.children != nil {
		t.Error("Adding an empty string as domain name should have no effect")
	}

	trie2 := new(domainTrie)
	trie.Add("google.com.")
	trie2.Add("google.com")
	if !reflect.DeepEqual(trie, trie2) {
		t.Error("Domain name normalization failed")
	}
}

func TestTrieAdd(t *testing.T) {
	trie := new(domainTrie)
	trie.Add("google.com")
	trie.Add(".")
	trie.Add("goo.gl")

	if !(trie.end && trie.children == nil) {
		t.Error("A dot should end at root.")
	}
	if !trie.Contain("www.google.com") || !trie.Contain("ietf.org") {
		t.Error("A dot should contain any domain name")
	}
}

func TestTrieContain(t *testing.T) {
	trie := new(domainTrie)
	if trie.Contain("goo.gl") {
		t.Error("An empty trie contains nothing")
	}

	trie.Add("google.com")
	trie.Add("api.github.com")
	trie.Add("cn.")

	if trie.Contain("www.github.com") {
		t.Error("api.github.com should not contain www.github.com")
	}
	if trie.Contain("github.com") {
		t.Error("api.github.com should not contain github.com")
	}
	if trie.Contain("ietf.org") || trie.Contain("twitter.com") {
		t.Error("What a shit have you written?")
	}

	if !trie.Contain("google.com") {
		t.Error("google.com should contain itself")
	}
	if !trie.Contain("api.github.com") {
		t.Error("api.github.com should contain itself")
	}
	if !trie.Contain("www.google.com") || !trie.Contain("mail.google.com") {
		t.Error("www.google.com and mail.google.com should be contained by google.com")
	}
	if !trie.Contain("google.com.") {
		t.Error("`google.com.` should be treated like `google.com`")
	}
	if !trie.Contain("www.google.com.") {
		t.Error("`www.google.com.` should be contained by `google.com`")
	}
	if !trie.Contain("12306.cn") {
		t.Error("cn should contain all .cn domains")
	}
}
