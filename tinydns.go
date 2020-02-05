package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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

const (
	CloudflareIPv4 = "1.1.1.1"
	CloudflareIPv6 = "2606:4700:4700::1111"
	ICMPv4         = 1  // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	ICMPv6         = 58 // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	HelloTinyDNS   = "HELLO-TINYDNS"
)

func ping6(ip net.IP, iface net.Interface) error {
	conn, err := icmp.ListenPacket("udp6", ip.String())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.Close()

	// https://en.wikipedia.org/wiki/Ping_(networking_utility)#Echo_request
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(HelloTinyDNS),
		},
	}
	writeBuf, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshalling: %w", err)
	}
	_, err = conn.WriteTo(writeBuf, &net.UDPAddr{IP: net.ParseIP(CloudflareIPv6), Zone: iface.Name})
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	replyBuf := make([]byte, iface.MTU)
	n, _, err := conn.ReadFrom(replyBuf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	replyMessage, err := icmp.ParseMessage(ICMPv6, replyBuf[:n])
	if err != nil {
		return fmt.Errorf("parsing: %w", err)
	}
	switch replyMessage.Type {
	case ipv6.ICMPTypeEchoReply:
		if echo, ok := replyMessage.Body.(*icmp.Echo); ok {
			if string(echo.Data) != HelloTinyDNS {
				return fmt.Errorf("got %q; want %q", HelloTinyDNS, string(echo.Data))
			}
		}
		return nil
	default:
		return fmt.Errorf("got %+v; want echo reply", replyMessage)
	}
}

func ping4(ip net.IP, iface net.Interface) error {
	conn, err := icmp.ListenPacket("udp4", ip.String())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.Close()

	// https://en.wikipedia.org/wiki/Ping_(networking_utility)#Echo_request
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(HelloTinyDNS),
		},
	}
	writeBuf, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshalling: %w", err)
	}
	_, err = conn.WriteTo(writeBuf, &net.UDPAddr{IP: net.ParseIP(CloudflareIPv4), Zone: iface.Name})
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	replyBuf := make([]byte, iface.MTU)
	n, _, err := conn.ReadFrom(replyBuf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	replyMessage, err := icmp.ParseMessage(ICMPv4, replyBuf[:n])
	if err != nil {
		return fmt.Errorf("parsing: %w", err)
	}
	switch replyMessage.Type {
	case ipv4.ICMPTypeEchoReply:
		if echo, ok := replyMessage.Body.(*icmp.Echo); ok {
			if string(echo.Data) != HelloTinyDNS {
				return fmt.Errorf("got %q; want %q", HelloTinyDNS, string(echo.Data))
			}
		}
		return nil
	default:
		return fmt.Errorf("got %+v; want echo reply", replyMessage)
	}
}

func ping(ip net.IP, iface net.Interface) error {
	if ip.To4() == nil {
		return ping6(ip, iface)
	} else {
		return ping4(ip, iface)
	}
}

func publicInterfaces() ([]net.Interface, error) {
	m := make(map[string]net.Interface, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, err
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			err = ping(ip, iface)
			if err != nil {
				return nil, fmt.Errorf("ping: %w", err)
			}

			m[iface.Name] = iface
		}
	}

	pubIfaces := make([]net.Interface, 0, len(m))
	for _, iface := range m {
		pubIfaces = append(pubIfaces, iface)
	}
	return pubIfaces, nil
}

func discoverLocalDNS() ([]net.IP, error) {
	m := make(map[string]net.IP)
	ifaces, err := publicInterfaces()
	if err != nil {
		return nil, fmt.Errorf("public interfaces: %w", err)
	}

	for _, iface := range ifaces {
		cl, err := nclient4.New(iface.Name, nclient4.WithTimeout(10*time.Second))
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 client: %w", err)
		}
		defer func() {
			err = cl.Close()
			if err != nil {
				log.Fatal(err)
			}
		}()

		offer, err := cl.DiscoverOffer(context.Background())
		if err != nil {
			return nil, fmt.Errorf("DHCP discover: %w", err)
		}
		for _, ip := range offer.DNS() {
			m[ip.String()] = ip
		}
	}
	dnsIPs := make([]net.IP, 0, len(m))
	for _, dnsIP := range m {
		dnsIPs = append(dnsIPs, dnsIP)
	}
	return dnsIPs, nil
}

func main() {
	dnsIPs, err := discoverLocalDNS()
	if err != nil {
		log.Fatal(err)
	}
	upstreamIP := dnsIPs[0].String()
	log.Printf("starting to listen on :53, upstream is %q", upstreamIP)
	server := dns.Server{Addr: ":53", Net: "udp"}
	b, err := NewTreeBlocker(upstreamIP+":53", "easylist.txt")
	if err != nil {
		log.Fatal(err)
	}
	server.Handler = dns.HandlerFunc(b.handler)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
