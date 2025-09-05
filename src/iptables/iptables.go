package iptables

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

func run(args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func existsChain(ipt, table, chain string) bool {
	_, err := run(ipt, "-w", "-t", table, "-S", chain)
	return err == nil
}

func ensureChain(ipt, table, chain string) {
	if !existsChain(ipt, table, chain) {
		_, _ = run(ipt, "-w", "-t", table, "-N", chain)
	}
}

func existsRule(ipt, table, chain string, spec []string) bool {
	_, err := run(append([]string{ipt, "-w", "-t", table, "-C", chain}, spec...)...)
	return err == nil
}

func delAll(ipt, table, chain string, spec []string) {
	for {
		_, err := run(append([]string{ipt, "-w", "-t", table, "-D", chain}, spec...)...)
		if err != nil {
			break
		}
	}
}

func setSysctlOrProc(name, val string) {
	_, _ = run("sh", "-c", "sysctl -w "+name+"="+val+" || echo "+val+" > /proc/sys/"+strings.ReplaceAll(name, ".", "/"))
}

func getSysctlOrProc(name string) string {
	out, _ := run("sh", "-c", "sysctl -n "+name+" 2>/dev/null || cat /proc/sys/"+strings.ReplaceAll(name, ".", "/"))
	return strings.TrimSpace(out)
}

func qbSpec(start, end int) []string {
	if end > start {
		return []string{"-j", "NFQUEUE", "--queue-balance",
			strconv.Itoa(start) + ":" + strconv.Itoa(end), "--queue-bypass"}
	}
	return []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(start), "--queue-bypass"}
}

type Rule struct {
	IPT    string
	Table  string
	Chain  string
	Spec   []string
	Action string
}

func (r Rule) Apply() error {
	if existsRule(r.IPT, r.Table, r.Chain, r.Spec) {
		return nil
	}
	op := "-A"
	if strings.ToUpper(r.Action) == "I" {
		op = "-I"
	}
	_, err := run(append([]string{r.IPT, "-w", "-t", r.Table, op, r.Chain}, r.Spec...)...)
	return err
}

func (r Rule) Remove() {
	delAll(r.IPT, r.Table, r.Chain, r.Spec)
}

type Chain struct {
	IPT   string
	Table string
	Name  string
}

func (c Chain) Ensure() {
	ensureChain(c.IPT, c.Table, c.Name)
}

func (c Chain) Remove() {
	if existsChain(c.IPT, c.Table, c.Name) {
		_, _ = run(c.IPT, "-w", "-t", c.Table, "-F", c.Name)
		_, _ = run(c.IPT, "-w", "-t", c.Table, "-X", c.Name)
	}
}

type SysctlSetting struct {
	Name    string
	Desired string
	Revert  string
}

var sysctlSnapPath = "/tmp/b4_sysctl_snapshot.json"

func loadSysctlSnapshot() map[string]string {
	b, err := os.ReadFile(sysctlSnapPath)
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return map[string]string{}
	}
	return m
}

func saveSysctlSnapshot(m map[string]string) {
	b, _ := json.Marshal(m)
	_ = os.WriteFile(sysctlSnapPath, b, 0600)
}

func (s SysctlSetting) Apply() {
	snap := loadSysctlSnapshot()
	if _, ok := snap[s.Name]; !ok {
		snap[s.Name] = getSysctlOrProc(s.Name)
		saveSysctlSnapshot(snap)
	}
	setSysctlOrProc(s.Name, s.Desired)
}

func (s SysctlSetting) RevertBack() {
	snap := loadSysctlSnapshot()
	if v, ok := snap[s.Name]; ok && v != "" {
		setSysctlOrProc(s.Name, v)
		delete(snap, s.Name)
		saveSysctlSnapshot(snap)
		return
	}
	setSysctlOrProc(s.Name, s.Revert)
}

type Manifest struct {
	Chains  []Chain
	Rules   []Rule
	Sysctls []SysctlSetting
}

func (m Manifest) Apply() error {
	for _, c := range m.Chains {
		c.Ensure()
	}
	for _, r := range m.Rules {
		if err := r.Apply(); err != nil {
			return err
		}
	}
	for _, s := range m.Sysctls {
		s.Apply()
	}
	return nil
}

func (m Manifest) RemoveRules() {
	for i := len(m.Rules) - 1; i >= 0; i-- {
		m.Rules[i].Remove()
	}
}

func (m Manifest) RemoveChains() {
	for i := len(m.Chains) - 1; i >= 0; i-- {
		m.Chains[i].Remove()
	}
}

func (m Manifest) RevertSysctls() {
	for _, s := range m.Sysctls {
		s.RevertBack()
	}
}

func hasBinary(name string) bool {
	_, err := run("sh", "-c", "command -v "+name)
	return err == nil
}

func buildManifest(cfg *config.Config) Manifest {
	var ipts []string
	if hasBinary("iptables") {
		ipts = append(ipts, "iptables")
	}
	if hasBinary("ip6tables") {
		ipts = append(ipts, "ip6tables")
	}
	if len(ipts) == 0 {
		ipts = []string{"iptables"}
	}
	start := cfg.QueueStartNum
	end := cfg.QueueStartNum + cfg.Threads - 1
	lanIf := "br0"
	wanIf := "eth0"
	markHex := fmt.Sprintf("0x%x/0xffffffff", cfg.Mark)

	var chains []Chain
	var rules []Rule

	for _, ipt := range ipts {
		b4 := Chain{IPT: ipt, Table: "mangle", Name: "B4"}
		chains = append(chains, b4)

		tcpRule := Rule{
			IPT: ipt, Table: "mangle", Chain: "B4", Action: "A",
			Spec: append([]string{"-p", "tcp", "--dport", "443", "-m", "mark", "!", "--mark", markHex, "-m", "connbytes", "--connbytes-dir", "original", "--connbytes-mode", "packets", "--connbytes", "0:19"}, qbSpec(start, end)...),
		}
		udpRule := Rule{
			IPT: ipt, Table: "mangle", Chain: "B4", Action: "A",
			Spec: append([]string{"-p", "udp", "--dport", "443", "-m", "mark", "!", "--mark", markHex, "-m", "connbytes", "--connbytes-dir", "original", "--connbytes-mode", "packets", "--connbytes", "0:8"}, qbSpec(start, end)...),
		}

		jumpPrerouting := Rule{IPT: ipt, Table: "mangle", Chain: "PREROUTING", Action: "A", Spec: []string{"-i", lanIf, "-m", "mark", "!", "--mark", markHex, "-j", "B4"}}
		jumpPostrouting := Rule{IPT: ipt, Table: "mangle", Chain: "POSTROUTING", Action: "A", Spec: []string{"-o", wanIf, "-m", "mark", "!", "--mark", markHex, "-j", "B4"}}
		jumpOutputTCP := Rule{IPT: ipt, Table: "mangle", Chain: "OUTPUT", Action: "I", Spec: []string{"-p", "tcp", "--dport", "443", "-m", "mark", "!", "--mark", markHex, "-j", "B4"}}
		jumpOutputUDP := Rule{IPT: ipt, Table: "mangle", Chain: "OUTPUT", Action: "I", Spec: []string{"-p", "udp", "--dport", "443", "-m", "mark", "!", "--mark", markHex, "-j", "B4"}}

		if existsChain(ipt, "mangle", "DIVERT") {
			divertReturnHTTPS := Rule{
				IPT:    ipt,
				Table:  "mangle",
				Chain:  "DIVERT",
				Action: "I",
				Spec:   []string{"-p", "tcp", "--dport", "443", "-j", "RETURN"},
			}
			rules = append(rules, divertReturnHTTPS)
		}

		rules = append(rules, jumpPrerouting, jumpPostrouting, jumpOutputTCP, jumpOutputUDP, tcpRule, udpRule)
	}

	sysctls := []SysctlSetting{
		{Name: "net.netfilter.nf_conntrack_checksum", Desired: "0", Revert: "1"},
		{Name: "net.netfilter.nf_conntrack_tcp_be_liberal", Desired: "1", Revert: "0"},
	}

	return Manifest{Chains: chains, Rules: rules, Sysctls: sysctls}
}

func delAnyJumpToB4(ipt, chain string) {
	out, _ := run(ipt, "-w", "-t", "mangle", "-S", chain)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !(strings.HasPrefix(line, "-A "+chain+" ") || strings.HasPrefix(line, "-I "+chain+" ")) {
			continue
		}
		if !strings.Contains(line, "-j B4") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		spec := fields[2:]
		_, _ = run(append([]string{ipt, "-w", "-t", "mangle", "-D", chain}, spec...)...)
	}
}

func AddRules(cfg *config.Config) error {
	if cfg.SkipIpTables {
		return nil
	}
	log.Infof("IPTABLES: adding rules")
	m := buildManifest(cfg)
	return m.Apply()
}

func ClearRules(cfg *config.Config) error {
	if cfg.SkipIpTables {
		return nil
	}
	ipts := []string{}
	if hasBinary("iptables") {
		ipts = append(ipts, "iptables")
	}
	if hasBinary("ip6tables") {
		ipts = append(ipts, "ip6tables")
	}
	if len(ipts) == 0 {
		ipts = []string{"iptables"}
	}
	m := buildManifest(cfg)
	m.RemoveRules()
	for _, ipt := range ipts {
		delAnyJumpToB4(ipt, "PREROUTING")
		delAnyJumpToB4(ipt, "POSTROUTING")
		delAnyJumpToB4(ipt, "OUTPUT")
	}
	time.Sleep(30 * time.Millisecond)
	m.RemoveChains()
	m.RevertSysctls()
	return nil
}
