package service

import (
	"regexp"
	"strings"
)

// signature 单条服务指纹：正则命中后取 name 作为服务名；
// name 为空时取第 1 捕获组（Web 服务器族）；versionGroup 指定版本所在的捕获组。
type signature struct {
	re           *regexp.Regexp
	name         string
	versionGroup int
}

var signatures = []signature{
	// SSH（先匹配 OpenSSH 提取版本，再兜底任意 SSH）
	{regexp.MustCompile(`SSH-[\d.]+-OpenSSH[_-]([\w.]+)`), "ssh", 1},
	{regexp.MustCompile(`SSH-[\d.]+-(\S+)`), "ssh", 1},
	// FTP
	{regexp.MustCompile(`(?i)(vsftpd|ProFTPD|Pure-FTPd|FileZilla)[ /]?v?([\w.]+)`), "ftp", 2},
	{regexp.MustCompile(`(?i)220[ -].{0,60}(FTP|FileZilla)`), "ftp", 0},
	// 邮件
	{regexp.MustCompile(`(?i)(Postfix|Exim|Sendmail|Microsoft ESMTP|Kerio Connect)[ /]?([\w.]+)?`), "smtp", 2},
	{regexp.MustCompile(`(?i)ESMTP`), "smtp", 0},
	{regexp.MustCompile(`(?i)IMAP4`), "imap", 0},
	{regexp.MustCompile(`(?i)POP3`), "pop3", 0},
	// 数据库 / 中间件
	{regexp.MustCompile(`(?i)(MariaDB|MySQL)[ /]?([\w.]+)?`), "mysql", 2},
	{regexp.MustCompile(`(?i)PostgreSQL[ /]?([\w.]+)?`), "postgresql", 1},
	{regexp.MustCompile(`(?i)MongoDB`), "mongodb", 0},
	{regexp.MustCompile(`(?i)Redis`), "redis", 0},
	{regexp.MustCompile(`(?i)Memcached`), "memcached", 0},
	{regexp.MustCompile(`(?i)Elasticsearch`), "elasticsearch", 0},
	{regexp.MustCompile(`(?i)(RabbitMQ|AMQP)`), "amqp", 0},
	{regexp.MustCompile(`(?i)Kafka`), "kafka", 0},
	// 远程访问 / 文件共享
	{regexp.MustCompile(`(?i)(Microsoft Terminal Services|x\.224|RDP)`), "rdp", 0},
	{regexp.MustCompile(`(?i)(SMB|NT LM|NetBIOS|Windows NT)`), "smb", 0},
	{regexp.MustCompile(`(?i)(RealVNC|TightVNC|TigerVNC|UltraVNC|RFB \d{3})`), "vnc", 0},
	{regexp.MustCompile(`(?i)Telnet`), "telnet", 0},
	// 其他
	{regexp.MustCompile(`(?i)(nginx|openresty|Apache|IIS|Tomcat|Jetty|WebLogic|JBoss|WildFly|Undertow|Caddy|lighttpd|Tornado|Werkzeug|gunicorn|uvicorn|Kestrel)[ /]?v?([\w.]+)?`), "", 2},
	{regexp.MustCompile(`(?i)HTTP/1\.[01] (\d{3})`), "http", 0},
}

// fingerprint 对 Banner 做指纹匹配，返回服务名与版本（未命中返回空串）。
func fingerprint(banner string) (string, string) {
	for _, sig := range signatures {
		m := sig.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		name := sig.name
		if name == "" && len(m) > 1 && m[1] != "" {
			name = strings.ToLower(m[1])
		}
		version := ""
		if sig.versionGroup > 0 && len(m) > sig.versionGroup {
			version = m[sig.versionGroup]
		}
		if name == "" {
			continue
		}
		return name, version
	}
	return "", ""
}

// wellKnownPorts 常见端口 → 服务名兜底映射。
var wellKnownPorts = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 113: "ident",
	119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "isakmp", 502: "modbus",
	514: "syslog", 515: "printer", 523: "dameng", 548: "afp", 554: "rtsp", 587: "smtp",
	593: "rpc-over-http", 623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync",
	902: "vmware-auth", 993: "imaps", 995: "pop3s", 1080: "socks", 1099: "java-rmi",
	1194: "openvpn", 1433: "mssql", 1434: "mssql-redirect", 1494: "citrix-ica",
	1521: "oracle", 1723: "pptp", 1812: "radius", 1883: "mqtt", 2049: "nfs",
	2181: "zookeeper", 2222: "ssh", 2375: "docker", 2376: "docker-tls",
	2379: "etcd-client", 2380: "etcd-peer", 3128: "squid-proxy", 3260: "iscsi",
	3268: "ldap-gc", 3269: "ldap-gc-ssl", 3306: "mysql", 3389: "rdp", 3690: "svn",
	4848: "glassfish", 5060: "sip", 5222: "xmpp", 5432: "postgresql", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-https", 6000: "x11",
	6379: "redis", 6443: "kubernetes-api", 6667: "irc", 7001: "weblogic",
	7002: "weblogic-ssl", 7077: "spark", 8000: "http-alt", 8008: "http-alt",
	8009: "ajp", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
	8848: "nacos", 8888: "http-alt", 9000: "http-alt", 9001: "http-alt",
	9090: "http-alt", 9092: "kafka", 9200: "elasticsearch", 9300: "es-transport",
	9418: "git", 9999: "http-alt", 10000: "webmin", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 50000: "db2",
}

// knownPortName 返回端口对应的常见服务名，未知返回 "unknown"。
func knownPortName(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return "unknown"
}
