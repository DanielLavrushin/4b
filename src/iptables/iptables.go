// iptables/iptables.go
package iptables

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

func run(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		log.Errorf("%v -> %v: %s", args, err, string(out))
	}
	return string(out), nil
}
func setSysctlOrProc(key, val string) {
	if _, err := exec.LookPath("sysctl"); err == nil {
		if _, err := run("sysctl", "-w", fmt.Sprintf("%s=%s", key, val)); err == nil {
			return
		}
	}
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	_ = os.WriteFile(path, []byte(val), 0644)
}
func tryModprobe(name string) bool {

	cmd := exec.Command("modprobe", name)
	_, err := cmd.CombinedOutput()

	if err != nil {
		return false
	}
	return true
}

func existsChain(ipt, table, chain string) bool {
	return exec.Command(ipt, "-w", "-t", table, "-L", chain, "-n").Run() == nil
}

func existsRule(ipt, table, chain string, spec []string) bool {
	args := append([]string{ipt, "-w", "-t", table, "-C", chain}, spec...)
	return exec.Command(args[0], args[1:]...).Run() == nil
}

func addOnce(ipt, table, chain string, spec []string) error {
	if existsRule(ipt, table, chain, spec) {
		return nil
	}
	_, err := run(append([]string{ipt, "-w", "-t", table, "-A", chain}, spec...)...)
	if err != nil {
		log.Errorf("Failed to append rule: %v", err)
	}
	return err
}
func insertOnce(ipt, table, chain string, spec []string) error {
	if existsRule(ipt, table, chain, spec) {
		return nil
	}
	_, err := run(append([]string{ipt, "-w", "-t", table, "-I", chain}, spec...)...)
	if err != nil {
		log.Errorf("Failed to insert rule: %v", err)
	}
	return err
}

func delAll(ipt, table, chain string, spec []string) {
	for existsRule(ipt, table, chain, spec) {
		run(append([]string{ipt, "-w", "-t", table, "-D", chain}, spec...)...)
	}
}

func ensureChain(ipt, table, chain string) {
	if !existsChain(ipt, table, chain) {
		run(ipt, "-w", "-t", table, "-N", chain)
	} else {
		run(ipt, "-w", "-t", table, "-F", chain)
	}
}

func qbSpec(start, end int) []string {
	if end <= start {
		return []string{"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", start), "--queue-bypass"}
	}
	return []string{"-j", "NFQUEUE", "--queue-balance", fmt.Sprintf("%d:%d", start, end), "--queue-bypass"}
}
func hasNFQueue(ipt string) bool {
	out, _ := exec.Command(ipt, "-j", "NFQUEUE", "-h").CombinedOutput()
	return bytes.Contains(bytes.ToUpper(out), []byte("NFQUEUE"))
}

func delAnyJumpToB4(ipt, chain string) {
	out, _ := exec.Command(ipt, "-w", "-t", "mangle", "-L", chain, "-n", "--line-numbers", "-v").CombinedOutput()
	lines := strings.Split(string(out), "\n")
	var nums []int
	for _, ln := range lines {
		// match any rule that jumps to B4 in this chain
		if strings.Contains(ln, " j B4") || strings.Contains(ln, " B4 ") {
			fs := strings.Fields(ln)
			if len(fs) > 0 {
				if n, err := strconv.Atoi(fs[0]); err == nil {
					nums = append(nums, n)
				}
			}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	for _, n := range nums {
		run(ipt, "-w", "-t", "mangle", "-D", chain, strconv.Itoa(n))
	}
}

func AddRules(cfg *config.Config) error {
	log.Infof("IPTABLES: adding rules")
	has_connbytes := tryModprobe("xt_connbytes")
	log.Infof("IPTABLES: connbytes support: %v", has_connbytes)
	const ipt = "iptables"
	ensureChain(ipt, "mangle", "B4")

	start := cfg.QueueStartNum
	end := cfg.QueueStartNum + cfg.Threads - 1

	addOnce(ipt, "mangle", "B4", append([]string{"-p",
		"tcp",
		"--dport", "443",
		"-m", "mark", "!", "--mark", fmt.Sprintf("%d/%d", cfg.Mark, cfg.Mark),
		"-m", "connbytes",
		"--connbytes-dir", "original",
		"--connbytes-mode", "packets",
		"--connbytes", "0:19"},
		qbSpec(start, end)...))

	addOnce(ipt, "mangle", "B4", append([]string{"-p",
		"udp",
		"--dport", "443",
		"-m", "mark", "!", "--mark", fmt.Sprintf("%d/%d", cfg.Mark, cfg.Mark),
		"-m", "connbytes",
		"--connbytes-dir", "original",
		"--connbytes-mode", "packets",
		"--connbytes", "0:8"},
		qbSpec(start, end)...))

	insertOnce(ipt, "mangle", "PREROUTING", []string{"-j", "B4"})
	insertOnce(ipt, "mangle", "POSTROUTING", []string{"-j", "B4"})
	insertOnce(ipt, "mangle", "OUTPUT", []string{"-j", "B4"})

	setSysctlOrProc("net.netfilter.nf_conntrack_checksum", "0")
	setSysctlOrProc("net.netfilter.nf_conntrack_tcp_be_liberal", "1")
	return nil
}

func ClearRules(cfg *config.Config) error {
	log.Infof("IPTABLES: clearing rules")

	const ipt = "iptables"
	start := cfg.QueueStartNum
	end := cfg.QueueStartNum + cfg.Threads - 1

	// Specs to remove
	tcpData := append([]string{"-p", "tcp", "--dport", "443", "-m", "length", "--length", "100:"}, qbSpec(start, end)...)
	udpOut := append([]string{"-p", "udp", "--dport", "443", "-m", "length", "--length", "1200:"}, qbSpec(start, end)...)
	udpPre := append([]string{"-p", "udp", "--dport", "443", "-m", "length", "--length", "1200:"}, qbSpec(start, end)...)

	// Remove NFQUEUE specs
	delAll(ipt, "mangle", "B4", tcpData)
	delAll(ipt, "mangle", "OUTPUT", udpOut)
	delAll(ipt, "mangle", "PREROUTING", udpPre)
	delAll(ipt, "mangle", "POSTROUTING", udpPre)

	delAll(ipt, "mangle", "OUTPUT", []string{"-m", "mark", "--mark", fmt.Sprintf("%d/%d", cfg.Mark, cfg.Mark), "-j", "ACCEPT"})

	// Remove jumps to B4 we added
	delAll(ipt, "mangle", "OUTPUT", []string{"-p", "tcp", "--dport", "443", "-j", "B4"})
	delAnyJumpToB4(ipt, "OUTPUT")      // sweep stragglers
	delAnyJumpToB4(ipt, "PREROUTING")  // if any were left
	delAnyJumpToB4(ipt, "POSTROUTING") // if any were left

	time.Sleep(30 * time.Millisecond)

	if existsChain(ipt, "mangle", "B4") {
		run(ipt, "-w", "-t", "mangle", "-F", "B4")
		run(ipt, "-w", "-t", "mangle", "-X", "B4")
	}

	setSysctlOrProc("net.netfilter.nf_conntrack_checksum", "1")
	setSysctlOrProc("net.netfilter.nf_conntrack_tcp_be_liberal", "0")
	return nil
}
