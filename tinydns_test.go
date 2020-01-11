package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestTree(t *testing.T) {
	// a -> b -> c
	//		  -> f
	// 		d -> e
	data := []string{"ads.example.com", "ads.example.net", "ads.agency.org", "klingt.net", "git.klingt.net", "foo.bar.cloudfront.com"}

	tree := NewTree()
	for _, s := range data {
		tree.Insert(strings.Split(s, "."))
	}

	require.Contains(t, tree.Nodes, "com")
	subTree := tree.Nodes["com"]
	require.NotNil(t, subTree)
	require.Contains(t, subTree.Nodes, "example")
	subSubTree := subTree.Nodes["example"]
	require.Contains(t, subSubTree.Nodes, "ads")

	require.Contains(t, tree.Nodes, "net")
	subTree = tree.Nodes["net"]
	require.NotNil(t, subTree)
	require.Contains(t, subTree.Nodes, "example")
	subSubTree = subTree.Nodes["example"]
	require.Contains(t, subSubTree.Nodes, "ads")

	subTree = tree.Nodes["org"]
	require.NotNil(t, subTree)
	require.Contains(t, subTree.Nodes, "agency")
	subSubTree = subTree.Nodes["agency"]
	require.Contains(t, subSubTree.Nodes, "ads")
}

func TestIsBlacklisted(t *testing.T) {
	tree := NewTree()
	for _, domain := range []string{"example.com", "ads.klingt.net"} {
		tree.Insert(strings.Split(domain, "."))
	}
	tb := treeBlocker{
		"",
		nil,
		tree,
	}

	tCases := map[string]struct {
		domain      string
		blacklisted bool
	}{
		"exact-match": {
			"example.com.",
			true,
		},
		"subdomain": {
			"sub.example.com.",
			true,
		},
		"not-blacklisted": {
			"example.net.",
			false,
		},
		"only-subdomain-blacklisted": {
			"klingt.net.",
			false,
		},
	}

	for name, tCase := range tCases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tCase.blacklisted, tb.isBlacklisted(tCase.domain))
		})
	}
}

type responseRecorder struct {
	t   *testing.T
	msg *dns.Msg
}

func newResponseRecorder(t *testing.T) *responseRecorder {
	return &responseRecorder{t, nil}
}

func (rr *responseRecorder) LocalAddr() net.Addr {
	rr.t.Fatal("unimplemented")
	return nil
}

func (rr *responseRecorder) RemoteAddr() net.Addr {
	rr.t.Fatal("unimplemented")
	return nil
}

func (rr *responseRecorder) WriteMsg(msg *dns.Msg) error {
	if rr.msg != nil {
		return fmt.Errorf("msg was already written: actual=(%v) new=(%v)", rr.msg, msg)
	}
	rr.msg = msg
	return nil
}

func (rr *responseRecorder) Write([]byte) (int, error) {
	rr.t.Fatal("unimplemented")
	return -1, fmt.Errorf("unimplemented")
}

func (rr *responseRecorder) Close() error {
	return fmt.Errorf("unimplemented")
}

func (rr *responseRecorder) TsigStatus() error {
	return fmt.Errorf("unimplemented")
}

func (rr *responseRecorder) TsigTimersOnly(bool) {
	rr.t.Fatal("unimplemented")
}

func (rr *responseRecorder) Hijack() {
	rr.t.Fatal("unimplemented")
}

func TestHandler(t *testing.T) {
	tb, err := NewTreeBlocker("1.1:53", "testlist.txt")
	require.NoError(t, err)

	tCases := map[string]struct {
		question    dns.Question
		blacklisted bool
	}{
		"exact-match": {
			dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			true,
		},
		"subdomain-match": {
			dns.Question{Name: "sub.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			true,
		},
		"only-subdomain-blacklisted": {
			dns.Question{Name: "klingt.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			false,
		},
		"not-blacklisted": {
			dns.Question{Name: "google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			false,
		},
	}
	for name, tCase := range tCases {
		t.Run(name, func(t *testing.T) {
			msg := &dns.Msg{
				// MsgHdr:   dns.MsgHdr{RecursionDesired: true, RecursionAvailable: true},
				Question: []dns.Question{tCase.question},
			}
			rr := newResponseRecorder(t)
			tb.handler(rr, msg)
			require.NotNil(t, rr.msg)
			require.True(t, rr.msg.Response, "not a response")
			require.NotEmptyf(t, rr.msg.Answer, "answer section empty: %#v", rr.msg)
			require.Len(t, rr.msg.Answer, 1)
			answer, ok := rr.msg.Answer[0].(*dns.A)
			require.True(t, ok, "answer not of type A")
			hdr := answer.Header()
			require.Equal(t, hdr.Name, tCase.question.Name)
			require.Equal(t, hdr.Rrtype, dns.TypeA)
			require.Greater(t, hdr.Ttl, uint32(0), "TTL is zero")
			require.Equal(t, answer.A.IsLoopback(), tCase.blacklisted)
		})
	}
}

func BenchmarkBlacklister(b *testing.B) {
	nb, err := NewNaiveBlocker("1.1:53", "easylist.txt")
	require.NoError(b, err)
	tb, err := NewTreeBlocker("1.1:53", "easylist.txt")
	require.NoError(b, err)

	data, err := ioutil.ReadFile("opendns-random-domains.txt")
	require.NoError(b, err)
	domains := strings.Split(string(data), "\n")

	b.Run("naive", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for _, domain := range domains {
				nb.isBlacklisted(domain)
			}
		}
	})

	b.Run("tree", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for _, domain := range domains {
				tb.isBlacklisted(domain)
			}
		}
	})
}
