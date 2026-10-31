package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// 与平台 apacheScanSchema 一致。Apache 的配置分散在多个文件里，还有条件块和变量：
// 自己解析出的文件清单和虚拟主机必须与 Apache 报告的逐项一致，遇到无法确定的写法整台拒绝，不猜
type apacheScan struct {
	Status        string          `json:"status"` // OK | ERROR
	Error         string          `json:"error,omitempty"`
	Location      *apacheLocation `json:"location,omitempty"`
	ReloadCommand string          `json:"reloadCommand,omitempty"`
	Sites         []apacheSite    `json:"sites"`
}

type apacheLocation struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Directive string `json:"directive"`
}

type apacheSite struct {
	ServerNames []string     `json:"serverNames"`
	CertPath    string       `json:"certPath"`
	KeyPath     string       `json:"keyPath"`
	ChainPath   *string      `json:"chainPath"`
	Certificate *certSummary `json:"certificate"`
	Renewal     *renewalInfo `json:"renewal"`
	Eligible    bool         `json:"eligible"`
	// SHARED_FILE | NAME_CONFLICT | MULTIPLE_CERTIFICATES | KEY_IN_CERTIFICATE
	Reason     string `json:"reason,omitempty"`
	SharedPath string `json:"sharedPath,omitempty"`
	// 每个虚拟主机在本机的连接地址和访问名称，部署后用来确认 Apache 已换上新证书
	endpoints []liveProbe
}

type apacheReject struct {
	code     string // CONFIG_FAILED | UNSUPPORTED_VERSION | UNSUPPORTED_CONFIG | MOD_MD | READ_FAILED
	location *apacheLocation
}

// 解析结果与 Apache 报告的对不上
var errApacheRead = &apacheReject{code: "READ_FAILED"}

func unsupportedAt(file string, line int, directive string) *apacheReject {
	return &apacheReject{code: "UNSUPPORTED_CONFIG", location: &apacheLocation{File: file, Line: line, Directive: directive}}
}

func scanApache() *apacheScan {
	inst, running := findApache()
	if inst == nil {
		if running {
			return &apacheScan{Status: "ERROR", Error: "NOT_SYSTEMD", Sites: []apacheSite{}}
		}
		return nil
	}
	sites, rej := discoverApache(inst)
	if rej != nil {
		return &apacheScan{Status: "ERROR", Error: rej.code, Location: rej.location, Sites: []apacheSite{}}
	}
	acme := loadAcmeShConfigs()
	for i := range sites {
		sites[i].Certificate = readCertSummary(sites[i].CertPath)
		sites[i].Renewal = detectRenewal(sites[i].CertPath, sites[i].KeyPath, acme)
	}
	return &apacheScan{Status: "OK", ReloadCommand: inst.reloadCommand(), Sites: sites}
}

// checkApacheLive 在本机连接使用这些证书文件的 Apache 站点，确认返回的是刚写入的证书
func checkApacheLive(files []fileSpec) *liveCheck {
	inst, _ := findApache()
	if inst == nil {
		return nil
	}
	sites, rej := discoverApache(inst)
	if rej != nil {
		return nil
	}
	var probes []liveProbe
	for _, f := range files {
		leaf := leafCertificate(f.Content)
		if leaf == nil {
			continue
		}
		for _, s := range sites {
			if !sameFile(s.CertPath, f.Path) {
				continue
			}
			for _, e := range s.endpoints {
				e.expected = sha256.Sum256(leaf.Raw)
				probes = append(probes, e)
			}
		}
	}
	if len(probes) == 0 {
		return nil
	}
	return waitLive(probes)
}

func sameFile(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

// apacheInstance 是 systemd 正在运行的 Apache。用主进程的程序、启动参数和环境变量执行只读命令，
// 读到的才是它实际加载的配置（Debian 的配置依赖 envvars 导出的变量，RHEL 的启动参数来自 sysconfig）
type apacheInstance struct {
	unit string
	exe  string
	args []string
	env  []string
}

// 没有由 systemd 运行的 Apache 时，running 表示是否有其他方式启动的 Apache 进程
func findApache() (inst *apacheInstance, running bool) {
	for _, unit := range []string{"apache2", "httpd"} {
		ctx, cancel := context.WithTimeout(context.Background(), scanCommandTimeout)
		out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=MainPID", "--value", unit).Output()
		cancel()
		pid := strings.TrimSpace(string(out))
		if err != nil || pid == "" || pid == "0" {
			continue
		}
		proc := "/proc/" + pid
		exe, err := os.Readlink(proc + "/exe")
		// 升级软件包后未重启时，原程序文件已被替换
		exe = strings.TrimSuffix(exe, " (deleted)")
		if err != nil || !isApacheBinary(exe) {
			continue
		}
		cmdline, err := os.ReadFile(proc + "/cmdline")
		if err != nil {
			continue
		}
		environ, err := os.ReadFile(proc + "/environ")
		if err != nil {
			continue
		}
		return &apacheInstance{unit: unit, exe: exe, args: apacheStartArgs(splitNul(cmdline)), env: splitNul(environ)}, true
	}
	// 容器里的进程在宿主机上也看得到，只算和客户端同一 PID 命名空间的
	self, _ := os.Readlink("/proc/self/ns/pid")
	comms, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, f := range comms {
		dir := filepath.Dir(f)
		ns, _ := os.Readlink(dir + "/ns/pid")
		if b, err := os.ReadFile(f); err == nil && ns == self && isApacheBinary(strings.TrimSpace(string(b))) {
			return nil, true
		}
	}
	return nil, false
}

func isApacheBinary(p string) bool {
	base := filepath.Base(p)
	return base == "apache2" || base == "httpd"
}

func splitNul(b []byte) []string {
	var out []string
	for _, s := range strings.Split(string(b), "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// 去掉程序名和 -k 启动控制参数，保留 -f、-d、-D 等决定配置内容的参数（FOREGROUND 也能被 IfDefine 判断）
func apacheStartArgs(cmdline []string) []string {
	var args []string
	for i := 1; i < len(cmdline); i++ {
		if cmdline[i] == "-k" {
			i++
			continue
		}
		args = append(args, cmdline[i])
	}
	return args
}

func (a *apacheInstance) output(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scanCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.exe, append(append([]string{}, a.args...), args...)...)
	cmd.Env = a.env
	return cmd.Output()
}

// graceful reload 遇到错误配置会让主进程退出，所以先检查配置。
// Debian 的 apache2ctl 会导出配置需要的环境变量，直接运行程序会因缺变量而检查失败
func (a *apacheInstance) reloadCommand() string {
	if a.unit == "apache2" {
		return "apache2ctl configtest && systemctl reload apache2"
	}
	parts := []string{shellQuote(a.exe)}
	for _, arg := range a.args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ") + " -t && systemctl reload " + a.unit
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./=:,+@%-]+$`)

func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var (
	reIncludeRef     = regexp.MustCompile(`^\s+\((\*|\d+)\) (.+)$`)
	reServerRoot     = regexp.MustCompile(`(?m)^ServerRoot: "(.*)"$`)
	reNameVhostAddr  = regexp.MustCompile(`^(\S+)\s+is a NameVirtualHost$`)
	reNameVhost      = regexp.MustCompile(`^\s+port \d+ namevhost (\S+) \((.*):(\d+)\)$`)
	reSingleVhost    = regexp.MustCompile(`^(\S+)\s+(\S+) \((.*):(\d+)\)$`)
	reVhostAlias     = regexp.MustCompile(`^\s+(?:wild )?alias (\S+)$`)
	reDirectiveOwner = regexp.MustCompile(`(?m)^(\S+) \(([^)]+)\)$`)
	// Define 的名称不能含冒号，${map:key} 是 RewriteMap 的写法，不做替换
	reApacheVar = regexp.MustCompile(`\$\{([^}:]+)\}`)
)

type includeRef struct{ file, parent string }

func discoverApache(inst *apacheInstance) ([]apacheSite, *apacheReject) {
	// -C、-c 在启动参数里直接写配置指令，读配置文件看不到
	for _, a := range inst.args {
		if strings.HasPrefix(a, "-C") || strings.HasPrefix(a, "-c") {
			return nil, errApacheRead
		}
	}
	if _, err := inst.output("-t"); err != nil {
		return nil, &apacheReject{code: "CONFIG_FAILED"}
	}
	includes, err := inst.output("-t", "-D", "DUMP_INCLUDES")
	if err != nil {
		return nil, errApacheRead
	}
	var tree []includeRef
	for _, line := range strings.Split(string(includes), "\n") {
		if m := reIncludeRef.FindStringSubmatch(line); m != nil {
			tree = append(tree, includeRef{file: m[2], parent: m[1]})
		}
	}
	// 2.4.23 之前（如 CentOS 7 的 2.4.6）没有这项输出，无法核对读到的文件是否完整
	if len(tree) == 0 {
		return nil, &apacheReject{code: "UNSUPPORTED_VERSION"}
	}
	vhostDump, err := inst.output("-S")
	if err != nil {
		return nil, errApacheRead
	}
	root := reServerRoot.FindSubmatch(vhostDump)
	if root == nil {
		return nil, errApacheRead
	}
	static, err := inst.output("-l")
	if err != nil {
		return nil, errApacheRead
	}
	directives, err := inst.output("-L")
	if err != nil {
		return nil, errApacheRead
	}

	p := newApacheParser(string(root[1]), inst, static, directives)
	if rej := p.read(tree[0].file, "*"); rej != nil {
		return nil, rej
	}
	if len(p.stack) != 0 || !sameIncludes(p.seen, tree) {
		return nil, errApacheRead
	}
	if rej := p.crossCheck(string(vhostDump)); rej != nil {
		return nil, rej
	}
	return p.sites()
}

func sameIncludes(a, b []includeRef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type apacheServer struct {
	file                string
	line                int
	bindings            []string
	name                string
	aliases             []string
	ssl                 string
	certs, keys, chains []string
}

type apacheContext struct {
	tag    string
	active bool
	server *apacheServer
}

type apacheParser struct {
	root    string
	defs    map[string]string
	env     map[string]string
	mods    map[string]bool
	dirMods map[string][]string
	seen    []includeRef
	stack   []apacheContext
	main    apacheServer
	mainSSL *apacheLocation
	vhosts  []*apacheServer
	listens []string
}

// 只在请求处理时生效的容器，里面不能写证书和站点名称（Apache 配置检查会报错），按普通作用域跳过
var requestContainers = map[string]bool{
	"directory": true, "directorymatch": true, "files": true, "filesmatch": true,
	"location": true, "locationmatch": true, "limit": true, "limitexcept": true,
	"proxy": true, "proxymatch": true, "if": true, "elseif": true, "else": true,
}

// 这些子命令会另外指定站点证书，按 SSLCertificateFile 读到的结果就不准了
var sslConfCertificateCommands = map[string]bool{
	"certificate": true, "privatekey": true, "chaincafile": true, "chaincapath": true,
}

func newApacheParser(root string, inst *apacheInstance, static, directives []byte) *apacheParser {
	p := &apacheParser{
		root:    root,
		defs:    map[string]string{},
		env:     map[string]string{},
		mods:    map[string]bool{},
		dirMods: map[string][]string{},
	}
	for i := 0; i < len(inst.args); i++ {
		if inst.args[i] == "-D" && i+1 < len(inst.args) {
			p.defs[inst.args[i+1]] = ""
			i++
		} else if name, ok := strings.CutPrefix(inst.args[i], "-D"); ok && name != "" {
			p.defs[name] = ""
		}
	}
	for _, kv := range inst.env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			p.env[k] = v
		}
	}
	// 编译进程序的模块，IfModule 既可以写源文件名 mod_ssl.c，也可以写模块名 ssl_module
	for _, line := range strings.Split(string(static), "\n") {
		if name := strings.TrimSpace(line); strings.HasSuffix(name, ".c") {
			p.mods[name] = true
			p.mods[strings.TrimSuffix(strings.TrimPrefix(name, "mod_"), ".c")+"_module"] = true
		}
	}
	for _, m := range reDirectiveOwner.FindAllStringSubmatch(string(directives), -1) {
		name := strings.ToLower(m[1])
		p.dirMods[name] = append(p.dirMods[name], m[2])
	}
	return p
}

func (p *apacheParser) read(file, parent string) *apacheReject {
	p.seen = append(p.seen, includeRef{file: file, parent: parent})
	if len(p.seen) > 5000 {
		return errApacheRead
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return errApacheRead
	}
	joined, start := "", 0
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		// Apache 只把行首的 # 当作注释
		if joined == "" {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			start = i + 1
		}
		if strings.HasSuffix(line, "\\") {
			joined += strings.TrimSuffix(line, "\\")
			continue
		}
		if rej := p.line(file, start, joined+line); rej != nil {
			return rej
		}
		joined = ""
	}
	if joined != "" {
		return errApacheRead
	}
	return nil
}

func (p *apacheParser) enabled() bool {
	for _, c := range p.stack {
		if !c.active {
			return false
		}
	}
	return true
}

func (p *apacheParser) server() *apacheServer {
	for i := len(p.stack) - 1; i >= 0; i-- {
		if p.stack[i].server != nil {
			return p.stack[i].server
		}
	}
	return &p.main
}

func (p *apacheParser) line(file string, n int, line string) *apacheReject {
	// 宏定义体不是实际配置，只有 Use 调用时才展开
	if len(p.stack) > 0 && p.stack[len(p.stack)-1].tag == "macro" {
		if strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(line, ">")), "</macro") {
			p.stack = p.stack[:len(p.stack)-1]
		}
		return nil
	}
	if strings.HasPrefix(line, "</") {
		tag := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line[2:], ">")))
		if len(p.stack) == 0 || p.stack[len(p.stack)-1].tag != tag {
			return errApacheRead
		}
		p.stack = p.stack[:len(p.stack)-1]
		return nil
	}
	if strings.HasPrefix(line, "<") {
		return p.openContainer(file, n, line)
	}
	if !p.enabled() {
		return nil
	}

	word, rest := cutWord(line)
	switch name := strings.ToLower(word); name {
	case "use":
		return unsupportedAt(file, n, word)
	case "mdomain", "mdcertificatefile", "mdcertificatekeyfile":
		return &apacheReject{code: "MOD_MD"}
	case "perlrequire", "perlmodule", "perlpostconfigrequire":
		return unsupportedAt(file, n, word)
	case "define", "undefine", "serverroot", "loadmodule", "include", "includeoptional", "listen",
		"servername", "serveralias", "sslengine", "sslcertificatefile", "sslcertificatekeyfile",
		"sslcertificatechainfile", "sslopensslconfcmd":
		args, ok := p.args(rest)
		if !ok || len(args) == 0 {
			return unsupportedAt(file, n, word)
		}
		return p.directive(file, n, word, name, args)
	}
	return nil
}

func (p *apacheParser) directive(file string, n int, word, name string, args []string) *apacheReject {
	s := p.server()
	switch name {
	case "define":
		if len(args) > 2 {
			return unsupportedAt(file, n, word)
		}
		p.defs[args[0]] = ""
		if len(args) == 2 {
			p.defs[args[0]] = args[1]
		}
	case "undefine":
		delete(p.defs, args[0])
	case "serverroot":
		p.root = p.path(args[0])
	case "loadmodule":
		if len(args) != 2 {
			return unsupportedAt(file, n, word)
		}
		p.mods[args[0]] = true
		p.mods[strings.TrimSuffix(filepath.Base(args[1]), ".so")+".c"] = true
	case "include", "includeoptional":
		if len(args) != 1 {
			return unsupportedAt(file, n, word)
		}
		files, rej := includeFiles(p.path(args[0]), name == "includeoptional")
		if rej != nil {
			return rej
		}
		for _, f := range files {
			if rej := p.read(f, strconv.Itoa(n)); rej != nil {
				return rej
			}
		}
	case "listen":
		p.listens = append(p.listens, args[0])
	case "servername":
		s.name = serverNameHost(args[0])
	case "serveralias":
		for _, a := range args {
			s.aliases = append(s.aliases, strings.ToLower(a))
		}
	case "sslengine":
		s.ssl = strings.ToLower(args[0])
		if s == &p.main && s.ssl == "on" {
			p.mainSSL = &apacheLocation{File: file, Line: n, Directive: word}
		}
	case "sslcertificatefile", "sslcertificatekeyfile", "sslcertificatechainfile":
		// pkcs11: 这类 URI 指向硬件或密钥库，不是能写入的文件
		if len(args) != 1 || (strings.Contains(args[0], ":") && !filepath.IsAbs(args[0])) {
			return unsupportedAt(file, n, word)
		}
		f := p.path(args[0])
		switch name {
		case "sslcertificatefile":
			s.certs = append(s.certs, f)
		case "sslcertificatekeyfile":
			s.keys = append(s.keys, f)
		default:
			s.chains = append(s.chains, f)
		}
	case "sslopensslconfcmd":
		if sslConfCertificateCommands[strings.ToLower(args[0])] {
			return unsupportedAt(file, n, word+" "+args[0])
		}
	}
	return nil
}

func (p *apacheParser) openContainer(file string, n int, line string) *apacheReject {
	word, _ := cutWord(line)
	if !strings.HasSuffix(line, ">") {
		return unsupportedAt(file, n, word)
	}
	inner := strings.TrimSpace(line[1 : len(line)-1])
	tagWord, rest := cutWord(inner)
	tag := strings.ToLower(tagWord)
	active := p.enabled()
	// 条件不成立的块里，Apache 不读取任何指令，只需要配对容器
	if !active {
		p.stack = append(p.stack, apacheContext{tag: tag})
		return nil
	}
	switch tag {
	case "macro":
		p.stack = append(p.stack, apacheContext{tag: tag})
	case "mdomain", "mdomainset":
		return &apacheReject{code: "MOD_MD"}
	case "ifmodule", "ifdefine", "ifdirective":
		arg, ok := p.subst(strings.TrimSpace(rest))
		if !ok || arg == "" || strings.ContainsAny(arg, " \t") {
			return unsupportedAt(file, n, "<"+tagWord+">")
		}
		neg := strings.HasPrefix(arg, "!")
		arg = strings.TrimPrefix(arg, "!")
		on := false
		switch tag {
		case "ifmodule":
			on = p.mods[arg]
		case "ifdefine":
			// 读取配置时带着 -D DUMP_*，按它判断的分支和运行时不一样
			if strings.HasPrefix(arg, "DUMP_") {
				return unsupportedAt(file, n, "<"+tagWord+" "+arg+">")
			}
			_, on = p.defs[arg]
		default:
			for _, m := range p.dirMods[strings.ToLower(arg)] {
				on = on || p.mods[m]
			}
		}
		p.stack = append(p.stack, apacheContext{tag: tag, active: on != neg})
	case "virtualhost":
		if p.server() != &p.main {
			return unsupportedAt(file, n, "<"+tagWord+">")
		}
		bindings, ok := p.args(rest)
		if !ok || len(bindings) == 0 {
			return unsupportedAt(file, n, "<"+tagWord+">")
		}
		v := &apacheServer{file: file, line: n, bindings: bindings}
		p.vhosts = append(p.vhosts, v)
		p.stack = append(p.stack, apacheContext{tag: tag, active: true, server: v})
	default:
		if !requestContainers[tag] {
			return unsupportedAt(file, n, "<"+tagWord+">")
		}
		p.stack = append(p.stack, apacheContext{tag: tag, active: true})
	}
	return nil
}

// 先按 Define 再按进程环境变量替换 ${NAME}；有替换不了的变量时 ok 为 false
func (p *apacheParser) subst(s string) (string, bool) {
	ok := true
	out := reApacheVar.ReplaceAllStringFunc(s, func(m string) string {
		k := m[2 : len(m)-1]
		if v, found := p.defs[k]; found {
			return v
		}
		if v, found := p.env[k]; found {
			return v
		}
		ok = false
		return m
	})
	return out, ok
}

func (p *apacheParser) args(s string) ([]string, bool) {
	s, ok := p.subst(s)
	if !ok {
		return nil, false
	}
	return apacheFields(s)
}

func (p *apacheParser) path(s string) string {
	if filepath.IsAbs(s) {
		return filepath.Clean(s)
	}
	return filepath.Join(p.root, s)
}

func cutWord(s string) (string, string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i:])
	}
	return s, ""
}

// apacheFields 按 Apache 的参数规则（ap_getword_conf）切分：空白分隔，引号内的空白不分隔。
// 反斜杠只在后面是反斜杠或当前引号时才算转义，其余原样保留
func apacheFields(s string) ([]string, bool) {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		var quote byte
		if c == '"' || c == '\'' {
			quote = c
			i++
		}
		var b strings.Builder
		j := i
		for ; j < len(s); j++ {
			if quote == 0 && (s[j] == ' ' || s[j] == '\t') || quote != 0 && s[j] == quote {
				break
			}
			if s[j] == '\\' && j+1 < len(s) && (s[j+1] == '\\' || quote != 0 && s[j+1] == quote) {
				j++
			}
			b.WriteByte(s[j])
		}
		if quote != 0 {
			if j >= len(s) {
				return nil, false
			}
			j++
		}
		out = append(out, b.String())
		i = j
	}
	return out, true
}

// Include 可以是通配符或目录，目录按文件名顺序递归读取
func includeFiles(pattern string, optional bool) ([]string, *apacheReject) {
	matches := []string{pattern}
	if strings.ContainsAny(pattern, "*?[") {
		var err error
		if matches, err = filepath.Glob(pattern); err != nil {
			return nil, errApacheRead
		}
	} else if _, err := os.Stat(pattern); err != nil {
		if optional {
			return nil, nil
		}
		return nil, errApacheRead
	}
	var files []string
	var walk func(string) *apacheReject
	walk = func(p string) *apacheReject {
		info, err := os.Stat(p)
		if err != nil {
			return errApacheRead
		}
		if !info.IsDir() {
			files = append(files, p)
			return nil
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return errApacheRead
		}
		for _, e := range entries {
			if rej := walk(filepath.Join(p, e.Name())); rej != nil {
				return rej
			}
		}
		return nil
	}
	for _, m := range matches {
		if rej := walk(m); rej != nil {
			return nil, rej
		}
	}
	return files, nil
}

// ServerName 可以带协议和端口，站点名称只取主机名
func serverNameHost(s string) string {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if !strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, ":"); i > 0 {
			s = s[:i]
		}
	}
	return strings.ToLower(s)
}

// splitBinding 把 VirtualHost 和 Listen 的地址拆成主机和端口，主机为 * 表示全部地址
func splitBinding(a string) (string, int, bool) {
	if isDigits(a) {
		port, err := strconv.Atoi(a)
		return "*", port, err == nil
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil || !isDigits(port) {
		return "", 0, false
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, false
	}
	if host == "*" || host == "_default_" {
		return "*", n, true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", 0, false
	}
	return ip.String(), n, true
}

type vhostRow struct {
	address, name, file string
	line                int
	aliases             []string
	aliasesShown        bool
}

func parseVhostDump(dump string) []vhostRow {
	var rows []vhostRow
	address := ""
	for _, line := range strings.Split(dump, "\n") {
		// 虚拟主机列表之后是 ServerRoot 等运行配置
		if strings.HasPrefix(line, "ServerRoot:") {
			break
		}
		if m := reNameVhostAddr.FindStringSubmatch(line); m != nil {
			address = m[1]
		} else if m := reNameVhost.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[3])
			rows = append(rows, vhostRow{address: address, name: m[1], file: m[2], line: n, aliasesShown: true})
		} else if m := reSingleVhost.FindStringSubmatch(line); m != nil {
			// 地址上只有一个虚拟主机时，Apache 不列出 ServerAlias
			n, _ := strconv.Atoi(m[4])
			rows = append(rows, vhostRow{address: m[1], name: m[2], file: m[3], line: n})
		} else if m := reVhostAlias.FindStringSubmatch(line); m != nil && len(rows) > 0 {
			rows[len(rows)-1].aliases = append(rows[len(rows)-1].aliases, strings.ToLower(m[1]))
		}
	}
	return rows
}

// crossCheck 要求解析出的每个虚拟主机（位置、地址、名称、别名）与 apachectl -S 完全一致。
// 配置里没写 ServerName 时，名称取 Apache 推导出的（通常是主机名）
func (p *apacheParser) crossCheck(dump string) *apacheReject {
	rows := parseVhostDump(dump)
	var expected, actual []string
	for _, v := range p.vhosts {
		name := v.name
		if name == "" {
			name = p.main.name
		}
		derived := map[string]bool{}
		for _, r := range rows {
			if r.file == v.file && r.line == v.line {
				derived[strings.ToLower(r.name)] = true
			}
		}
		if name == "" {
			if len(derived) != 1 {
				return errApacheRead
			}
			for n := range derived {
				name = n
			}
		}
		for _, b := range v.bindings {
			host, port, ok := splitBinding(b)
			if !ok {
				return unsupportedAt(v.file, v.line, "<VirtualHost "+b+">")
			}
			// 别名只在同一地址有多个虚拟主机时列出，按每个地址各自的输出核对
			aliases := v.aliases
			for _, r := range rows {
				if rh, rp, _ := splitBinding(r.address); r.file == v.file && r.line == v.line && rh == host && rp == port && !r.aliasesShown {
					aliases = nil
				}
			}
			expected = append(expected, vhostKey(v.file, v.line, host, port, name, aliases))
		}
	}
	for _, r := range rows {
		host, port, ok := splitBinding(r.address)
		if !ok {
			return errApacheRead
		}
		actual = append(actual, vhostKey(r.file, r.line, host, port, strings.ToLower(r.name), r.aliases))
	}
	sort.Strings(expected)
	sort.Strings(actual)
	if strings.Join(expected, "\n") != strings.Join(actual, "\n") {
		return errApacheRead
	}
	return nil
}

func vhostKey(file string, line int, host string, port int, name string, aliases []string) string {
	sorted := append([]string{}, aliases...)
	sort.Strings(sorted)
	return strings.Join([]string{file, strconv.Itoa(line), host, strconv.Itoa(port), name, strings.Join(sorted, ",")}, "\x00")
}

// 只有能对应到证书的名称：通配符只支持最左一级的 *.
func siteNames(v *apacheServer, main *apacheServer) ([]string, bool) {
	name := v.name
	if name == "" {
		name = main.name
	}
	var names []string
	for _, n := range append([]string{name}, v.aliases...) {
		if n == "" || net.ParseIP(n) != nil || !strings.Contains(n, ".") {
			continue
		}
		if strings.ContainsAny(strings.TrimPrefix(n, "*."), "*?[]") {
			return nil, false
		}
		if !contains(names, n) {
			names = append(names, n)
		}
	}
	return names, true
}

func namesOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if mx, _ := path.Match(x, y); mx {
				return true
			}
			if my, _ := path.Match(y, x); my {
				return true
			}
		}
	}
	return false
}

// sites 把启用 TLS 的虚拟主机按证书、私钥、证书链文件归并成站点。
// 文件只要被另一组站点引用，替换它就会影响那些站点，两边都不能接管
func (p *apacheParser) sites() ([]apacheSite, *apacheReject) {
	if p.mainSSL != nil {
		return nil, unsupportedAt(p.mainSSL.File, p.mainSSL.Line, p.mainSSL.Directive)
	}
	type group struct {
		site  apacheSite
		files map[int]string // 文件编号 -> 配置里的路径
	}
	var groups []*group
	byKey := map[string]*group{}
	owners := map[int]map[*group]bool{}
	// 按实际文件编号，符号链接和硬链接指向同一个文件时编号相同
	var stats []os.FileInfo
	fileID := func(f string) (int, bool) {
		info, err := os.Stat(f)
		if err != nil {
			return 0, false
		}
		for i, other := range stats {
			if os.SameFile(info, other) {
				return i, true
			}
		}
		stats = append(stats, info)
		return len(stats) - 1, true
	}
	// 证书和私钥按位置覆盖全局配置，全局多出来的几组仍然生效；证书链文件只有一个，有就整体覆盖
	merge := func(local, inherited []string) []string {
		if len(inherited) > len(local) {
			return append(append([]string{}, local...), inherited[len(local):]...)
		}
		return local
	}
	pick := func(local, inherited []string) []string {
		if len(local) > 0 {
			return local
		}
		return inherited
	}
	for i, v := range p.vhosts {
		ssl := v.ssl
		if ssl == "" {
			ssl = p.main.ssl
		}
		if ssl != "on" {
			continue
		}
		certs, keys, chains := merge(v.certs, p.main.certs), merge(v.keys, p.main.keys), pick(v.chains, p.main.chains)
		if len(certs) == 0 {
			return nil, errApacheRead
		}
		names, ok := siteNames(v, &p.main)
		if !ok {
			return nil, unsupportedAt(v.file, v.line, "ServerAlias")
		}
		files := map[int]string{}
		var ids []int
		for _, f := range append(append(append([]string{}, certs...), keys...), chains...) {
			id, ok := fileID(f)
			if !ok {
				return nil, errApacheRead
			}
			files[id] = f
			ids = append(ids, id)
		}

		reason := ""
		switch {
		case len(certs) > 1 || len(keys) > 1 || len(chains) > 1:
			reason = "MULTIPLE_CERTIFICATES"
		case len(keys) == 0 || ids[0] == ids[1]:
			reason = "KEY_IN_CERTIFICATE"
		}
		key := "vhost:" + strconv.Itoa(i)
		if reason == "" {
			key = fmt.Sprint(ids)
		}
		g := byKey[key]
		if g == nil {
			g = &group{files: files, site: apacheSite{ServerNames: []string{}, CertPath: certs[0], Reason: reason}}
			if len(keys) > 0 {
				g.site.KeyPath = keys[0]
			}
			if len(chains) > 0 {
				g.site.ChainPath = &chains[0]
			}
			byKey[key] = g
			groups = append(groups, g)
		}
		for id := range files {
			if owners[id] == nil {
				owners[id] = map[*group]bool{}
			}
			owners[id][g] = true
		}
		for _, n := range names {
			if !contains(g.site.ServerNames, n) {
				g.site.ServerNames = append(g.site.ServerNames, n)
			}
		}
		// 合并后的站点可能分布在不同端口，每个地址用该虚拟主机自己的名称连接
		for _, a := range p.endpoints(v) {
			if e := (liveProbe{address: a, serverName: probeServerName(names)}); !slices.Contains(g.site.endpoints, e) {
				g.site.endpoints = append(g.site.endpoints, e)
			}
		}
		if g.site.Reason == "" && p.nameConflict(v) {
			g.site.Reason = "NAME_CONFLICT"
		}
	}

	sites := make([]apacheSite, 0, len(groups))
	for _, g := range groups {
		if g.site.Reason == "" {
			for id, configured := range g.files {
				if len(owners[id]) > 1 {
					g.site.Reason, g.site.SharedPath = "SHARED_FILE", configured
					break
				}
			}
		}
		g.site.Eligible = g.site.Reason == ""
		sites = append(sites, g.site)
	}
	return sites, nil
}

// 同一端口上还有别的虚拟主机用了相同（或被通配符覆盖）的名称：同一地址时取决于配置顺序，
// 指定 IP 和 * 并存时，连到那个 IP 的访问者拿到的是指定 IP 的站点
func (p *apacheParser) nameConflict(v *apacheServer) bool {
	names, _ := siteNames(v, &p.main)
	for _, other := range p.vhosts {
		if other == v {
			continue
		}
		otherNames, _ := siteNames(other, &p.main)
		if !namesOverlap(names, otherNames) {
			continue
		}
		for _, a := range v.bindings {
			for _, b := range other.bindings {
				ha, pa, okA := splitBinding(a)
				hb, pb, okB := splitBinding(b)
				if okA && okB && pa == pb && (ha == hb || ha == "*" || hb == "*") {
					return true
				}
			}
		}
	}
	return false
}

// endpoints 按 Listen 找出虚拟主机在本机可连接的地址；监听全部地址时连回环地址
func (p *apacheParser) endpoints(v *apacheServer) []string {
	var out []string
	for _, b := range v.bindings {
		vh, vp, ok := splitBinding(b)
		if !ok {
			continue
		}
		for _, l := range p.listens {
			lh, lp, ok := splitBinding(l)
			if !ok || lp != vp || (vh != "*" && lh != "*" && lh != "0.0.0.0" && lh != "::" && lh != vh) {
				continue
			}
			host := vh
			if host == "*" {
				host = lh
			}
			switch host {
			case "*", "0.0.0.0":
				host = "127.0.0.1"
			case "::":
				host = "::1"
			}
			if a := net.JoinHostPort(host, strconv.Itoa(vp)); !contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}
