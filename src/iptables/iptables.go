package iptables

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("%v -> %v: %s", args, err, string(out))
	}
	return err
}

func tryModprobe(name string) { _ = run("modprobe", name) }

func existsChain(ipt, table, chain string) bool {
	return exec.Command(ipt, "-w", "-t", table, "-L", chain, "-n").Run() == nil
}

func existsRule(bin, table, chain string, spec []string) bool {
	args := append([]string{bin, "-w", "-t", table, "-C", chain}, spec...)
	return exec.Command(args[0], args[1:]...).Run() == nil
}

func addOnce(bin, table, chain string, spec []string) error {
	if existsRule(bin, table, chain, spec) {
		return nil
	}
	return run(append([]string{bin, "-w", "-t", table, "-A", chain}, spec...)...)
}

func delAll(bin, table, chain string, spec []string) {
	for existsRule(bin, table, chain, spec) {
		_ = run(append([]string{bin, "-w", "-t", table, "-D", chain}, spec...)...)
	}
}

func ensureChain(bin, table, chain string) {
	if exec.Command(bin, "-w", "-t", table, "-L", chain, "-n").Run() != nil {
		_ = run(bin, "-w", "-t", table, "-N", chain)
	} else {
		_ = run(bin, "-w", "-t", table, "-F", chain)
	}
}

func qbSpec(start, end int) []string {
	if end <= start {
		return []string{"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", start), "--queue-bypass"}
	}
	return []string{"-j", "NFQUEUE", "--queue-balance", fmt.Sprintf("%d:%d", start, end), "--queue-bypass"}
}

func delAnyJumpToB4(ipt, chain string) {
	out, _ := exec.Command(ipt, "-w", "-t", "mangle", "-L", chain, "-n", "--line-numbers", "-v").CombinedOutput()

	lines := strings.Split(string(out), "\n")
	var nums []int
	for _, ln := range lines {
		if strings.Contains(ln, " B4") && strings.Contains(ln, " j B4") || strings.Contains(ln, " B4 ") {
			f := strings.Fields(ln)
			if len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					nums = append(nums, n)
				}
			}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	for _, n := range nums {
		_ = run("iptables", "-w", "-t", "mangle", "-D", chain, strconv.Itoa(n))
	}
}

func disableOffloads(iface string) {
	if iface == "" {
		return
	}
	_ = run("ethtool", "-K", iface, "gro", "off")
	_ = run("ethtool", "-K", iface, "gso", "off")
	_ = run("ethtool", "-K", iface, "tso", "off")
}

func AddRules(cfg *config.Config) error {
	log.Infof("IPTABLES: adding rules")
	tryModprobe("xt_connbytes")

	// apply to IPv4 and IPv6
	for _, ipt := range []string{"iptables", "ip6tables"} {
		ensureChain(ipt, "mangle", "B4")

		// jump into B4 for tcp/443
		_ = addOnce(ipt, "mangle", "OUTPUT", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})
		_ = addOnce(ipt, "mangle", "PREROUTING", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})
		_ = addOnce(ipt, "mangle", "POSTROUTING", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})

		start := cfg.QueueStartNum
		end := cfg.QueueStartNum + cfg.Threads - 1

		// TCP: first N packets from client
		tcpConnbytes := append([]string{
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", fmt.Sprintf("3:%d", 2+cfg.ConnBytesLimit), // e.g. 0:21
			"--connbytes-dir", "original", "--connbytes-mode", "packets",
		}, qbSpec(start, end)...)
		_ = addOnce(ipt, "mangle", "B4", tcpConnbytes)

		// (optional) fallback PSH/ACK
		ctPsh := append([]string{
			"-p", "tcp",
			"-m", "conntrack", "--ctstate", "ESTABLISHED",
			"-m", "tcp", "--tcp-flags", "PSH,ACK", "PSH,ACK",
			"-m", "length", "--length", "80:", // avoid ACK‑only tiny segments
		}, qbSpec(start, end)...)
		_ = addOnce(ipt, "mangle", "B4", ctPsh)

		// QUIC: large UDP Initials (works well for both v4 and v6)
		udpOut := append([]string{
			"-p", "udp", "--dport", "443",
			"-m", "length", "--length", "1200:",
		}, qbSpec(start, end)...)
		_ = addOnce(ipt, "mangle", "OUTPUT", udpOut)

		udpPre := append([]string{
			"-p", "udp", "--dport", "443",
			"-m", "length", "--length", "1200:",
		}, qbSpec(start, end)...)
		_ = addOnce(ipt, "mangle", "PREROUTING", udpPre)

	}

	_ = run("sysctl", "-w", "net.netfilter.nf_conntrack_checksum=0")
	_ = run("sysctl", "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1")
	return nil
}

func ClearRules(cfg *config.Config) error {
	log.Infof("IPTABLES: clearing rules")
	for _, ipt := range []string{"iptables", "ip6tables"} {
		start := cfg.QueueStartNum
		end := cfg.QueueStartNum + cfg.Threads - 1

		udpOut := append([]string{"-p", "udp", "--dport", "443", "-m", "length", "--length", "1200:"}, qbSpec(start, end)...)
		udpPre := append([]string{"-p", "udp", "--dport", "443", "-m", "length", "--length", "1200:"}, qbSpec(start, end)...)
		tcpConnbytes := append([]string{"-p", "tcp", "-m", "connbytes", "--connbytes", fmt.Sprintf("3:%d", 2+cfg.ConnBytesLimit), "--connbytes-dir", "original", "--connbytes-mode", "packets"}, qbSpec(start, end)...)
		ctPsh := append([]string{"-p", "tcp", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "tcp", "--tcp-flags", "PSH,ACK", "PSH,ACK"}, qbSpec(start, end)...)

		delAll(ipt, "mangle", "OUTPUT", udpOut)
		delAll(ipt, "mangle", "PREROUTING", udpPre)
		delAll(ipt, "mangle", "B4", tcpConnbytes)
		delAll(ipt, "mangle", "B4", ctPsh)

		delAll(ipt, "mangle", "OUTPUT", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})
		delAll(ipt, "mangle", "PREROUTING", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})
		delAll(ipt, "mangle", "POSTROUTING", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})

		delAnyJumpToB4(ipt, "OUTPUT")
		delAnyJumpToB4(ipt, "PREROUTING")

		time.Sleep(30 * time.Millisecond)
		if existsChain(ipt, "mangle", "B4") {
			_ = run(ipt, "-w", "-t", "mangle", "-F", "B4")
			_ = run(ipt, "-w", "-t", "mangle", "-X", "B4")
		}
	}

	_ = run("sysctl", "-w", "net.netfilter.nf_conntrack_checksum=1")
	_ = run("sysctl", "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=0")
	return nil
}
