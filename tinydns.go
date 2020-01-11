package main

import (
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// block list
// format description: https://adblockplus.org/filter-cheatsheet
// $ curl --silent --fail 'https://easylist.to/easylist/easylist.txt' | grep -e '^||.*\^$' | sed -E 's/^\|\|(.*)\^$/\1/'

var (
	localhostA    = net.IPv4(127, 0, 0, 1)
	localhostAAAA = net.ParseIP("::1")
)

func answer(qtype uint16, domain string) dns.RR {
	switch qtype {
	case dns.TypeA:
		return &dns.A{
			A:   localhostA,
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			AAAA: localhostAAAA,
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		}
	}
	return nil
}

type Blocker interface {
	isBlacklisted(domain string) bool
}

type Tree struct {
	Nodes map[string]*Tree
}

func NewTree() *Tree {
	return &Tree{
		Nodes: make(map[string]*Tree),
	}
}

func (tree *Tree) Print(indent string) {
	for k, t := range tree.Nodes {
		arrow := ""
		if t != nil {
			arrow = "↴"
		}
		log.Println(indent + k + arrow)
		if t != nil {
			t.Print(indent + "\t")
		}
	}
}

func (tree *Tree) Insert(list []string) {
	if len(list) == 0 {
		return
	}
	idx := len(list) - 1
	element := list[idx]

	node, ok := tree.Nodes[element]
	if !ok {
		if idx == 0 {
			tree.Nodes[element] = nil
		} else {
			t := NewTree()
			t.Insert(list[:idx])
			tree.Nodes[element] = t
		}
	} else {
		if node == nil {
			node = NewTree()
			tree.Nodes[element] = node
		}
		node.Insert(list[:idx])
	}
}

type treeBlocker struct {
	upstream  string
	client    *dns.Client
	blacklist *Tree
}

func NewTreeBlocker(upstream string, blockfile string) (*treeBlocker, error) {
	data, err := ioutil.ReadFile(blockfile)
	if err != nil {
		return nil, err
	}

	tree := NewTree()
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		tree.Insert(strings.Split(trimmed, "."))
	}

	return &treeBlocker{
		upstream:  upstream,
		client:    &dns.Client{},
		blacklist: tree,
	}, nil
}

func splitAndReverse(delim string, s string) []string {
	split := strings.Split(s, delim)
	length := len(split)
	parts := make([]string, length)
	for idx, part := range split {
		parts[length-(idx+1)] = part
	}
	return parts
}

func (b *treeBlocker) isBlacklisted(domain string) bool {
	parts := splitAndReverse(".", strings.TrimRight(domain, "."))

	tree := b.blacklist
	for _, part := range parts {
		t, ok := tree.Nodes[part]
		if !ok {
			return false
		}
		if t == nil {
			return true
		}
		tree = t
	}
	return tree.Nodes == nil
}

func (b *treeBlocker) handler(w dns.ResponseWriter, r *dns.Msg) {
	for _, question := range r.Question {
		switch question.Qtype {
		case dns.TypeA:
			if b.isBlacklisted(question.Name) {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Answer = append(m.Answer, answer(question.Qtype, question.Name))
				err := w.WriteMsg(m)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				in, _, err := b.client.Exchange(r, b.upstream)
				if err != nil {
					log.Fatal(err)
				}

				err = w.WriteMsg(in)
				if err != nil {
					log.Fatal(err)
				}
			}
		case dns.TypeAAAA:
			if b.isBlacklisted(question.Name) {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Answer = append(m.Answer, answer(question.Qtype, question.Name))
				err := w.WriteMsg(m)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				in, _, err := b.client.Exchange(r, b.upstream)
				if err != nil {
					log.Fatal(err)
				}

				err = w.WriteMsg(in)
				if err != nil {
					log.Fatal(err)
				}
			}
		default:
			in, _, err := b.client.Exchange(r, b.upstream)
			if err != nil {
				log.Fatal(err)
			}

			err = w.WriteMsg(in)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

type naiveBlocker struct {
	upstream  string
	client    *dns.Client
	blacklist map[string]interface{}
}

func NewNaiveBlocker(upstream string, blockfile string) (*naiveBlocker, error) {
	blacklist := make(map[string]interface{})

	data, err := ioutil.ReadFile(blockfile)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if _, ok := blacklist[trimmed]; !ok {
			blacklist[trimmed] = nil
		}
	}

	return &naiveBlocker{
		upstream:  upstream,
		client:    &dns.Client{},
		blacklist: blacklist,
	}, nil
}

func (b *naiveBlocker) isBlacklisted(domain string) bool {
	domain = strings.TrimRight(domain, ".")
	for suffix := range b.blacklist {
		if strings.HasSuffix(domain, suffix) {
			if len(domain) == len(suffix) {
				return true
			}
			subdomain := strings.TrimSuffix(domain, suffix)
			if subdomain[len(subdomain)-1] == '.' {
				return true
			}
		}
	}
	return false
}

func (b *naiveBlocker) handler(w dns.ResponseWriter, r *dns.Msg) {
	for _, question := range r.Question {
		switch question.Qtype {
		case dns.TypeA:
			if b.isBlacklisted(question.Name) {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Answer = append(m.Answer, answer(question.Qtype, question.Name))
				w.WriteMsg(m)
			} else {
				in, _, err := b.client.Exchange(r, b.upstream)
				if err != nil {
					log.Fatal(err)
				}

				w.WriteMsg(in)
			}
		case dns.TypeAAAA:
			if b.isBlacklisted(question.Name) {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Answer = append(m.Answer, answer(question.Qtype, question.Name))
				w.WriteMsg(m)
			} else {
				in, _, err := b.client.Exchange(r, b.upstream)
				if err != nil {
					log.Fatal(err)
				}

				w.WriteMsg(in)
			}
		default:
			in, _, err := b.client.Exchange(r, b.upstream)
			if err != nil {
				log.Fatal(err)
			}

			w.WriteMsg(in)
		}
	}
}

func main() {
	server := dns.Server{Addr: ":10053", Net: "udp"}
	b, err := NewTreeBlocker("1.1:53", "easylist.txt")
	if err != nil {
		log.Fatal(err)
	}
	server.Handler = dns.HandlerFunc(b.handler)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
