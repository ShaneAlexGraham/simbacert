package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v2"
)

const shortUsage = `Usage of simba-cert:

	$ simba-cert -deploy example-config.yml
	Generate and Install certificates from config (can be used with -uninstall and -CAROOT options)

	$ simba-cert -install
	Install the local CA in the system trust store.

	$ simba-cert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ simba-cert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ simba-cert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ simba-cert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-deploy CONFIG
		Choose path to config yml file

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-CAROOT
	    Print the CA certificate and key storage location.

	$CAROOT (environment variable)
	    Set the CA certificate and key storage location. (This allows
	    maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		deployFlag    = flag.String("deploy", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "simba-cert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println((&simbacert{}).getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	var service = (&simbacert{
		configPath: *deployFlag, installMode: *installFlag, uninstallMode: *uninstallFlag, csrPath: *csrFlag,
		pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, client: *clientFlag,
		certFile: *certFileFlag, keyFile: *keyFileFlag, p12File: *p12FileFlag,
	})
	if *deployFlag != "" {
		service.Deploy(flag.Args())
	} else {
		service.Run(flag.Args())
	}
}

var rootName = "rootCA.pem"
var rootKeyName = "rootCA-key.pem"

type Conf struct {
	Organization       string `yaml:"organization"`
	OrganizationalUnit string `yaml:"organizational-unit"`
	Ca                 struct {
		CAROOT     string `yaml:"CAROOT"`
		CommonName string `yaml:"common-name"`
		CertName   string `yaml:"cert-name"`
		KeyName    string `yaml:"key-name"`
		P12File    string `yaml:"p12-file"`
		CsrPath    string `yaml:"csr-path"`
		Pkcs12     bool   `yaml:"pkcs12"`
		Ecdsa      bool   `yaml:"ecdsa"`
	} `yaml:"ca"`
	Certificates []struct {
		Name           string   `yaml:"name"`
		Type           string   `yaml:"type"`
		CertFile       string   `yaml:"cert-file"`
		KeyFile        string   `yaml:"key-file"`
		P12File        string   `yaml:"p12-file"`
		CsrPath        string   `yaml:"csr-path"`
		Pkcs12         bool     `yaml:"pkcs12"`
		Ecdsa          bool     `yaml:"ecdsa"`
		IncludeNetwork bool     `yaml:"include-network"`
		Hosts          []string `yaml:"hosts"`
	} `yaml:"certificates"`
}

type simbacert struct {
	installMode, uninstallMode bool
	pkcs12, ecdsa, client      bool
	keyFile, certFile, p12File string
	csrPath                    string
	configPath                 string

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool

	config Conf
}

func (c *Conf) getConf(file string) error {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return err
	}
	return nil
}

func (m *simbacert) Deploy(args []string) {
	fatalIfErr(m.config.getConf(m.configPath), "Failed to get deployment config")
	m.CAROOT = m.getCAROOT()

	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}

	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	if m.uninstallMode {
		m.uninstall()
		return
	}

	(&simbacert{
		installMode: true,
		config:      m.config,
	}).Run([]string{})

	if m.installMode {
		return
	}

	for _, certificate := range m.config.Certificates {
		var isClient = false

		if certificate.Type == "" {
			certificate.Type = "server"
		} else if certificate.Type == "client" {
			isClient = true
		}

		if certificate.CertFile == "" {
			if certificate.Name != "" {
				certificate.CertFile = fmt.Sprintf("%s-cert.pem", certificate.Name)
			} else {
				certificate.CertFile = fmt.Sprintf("%s-cert.pem", certificate.Type)
			}
		}

		if certificate.KeyFile == "" {
			if certificate.Name != "" {
				certificate.KeyFile = fmt.Sprintf("%s-key.pem", certificate.Name)
			} else {
				certificate.KeyFile = fmt.Sprintf("%s-key.pem", certificate.Type)
			}
		}

		if certificate.IncludeNetwork == true {
			foo, err := net.InterfaceAddrs()
			if err == nil {
				for _, v := range foo {
					ipAddr := strings.Split(v.String(), "/")
					certificate.Hosts = append(certificate.Hosts, ipAddr[0])
				}
			}
			certificate.Hosts = removeDuplicateValues(certificate.Hosts)
		}

		(&simbacert{
			csrPath:  certificate.CsrPath,
			pkcs12:   certificate.Pkcs12,
			ecdsa:    certificate.Ecdsa,
			client:   isClient,
			certFile: certificate.CertFile,
			keyFile:  certificate.KeyFile,
			p12File:  certificate.P12File,
			config:   m.config,
		}).Run(certificate.Hosts)
	}

}

func (m *simbacert) Run(args []string) {
	m.CAROOT = m.getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	if m.installMode {
		m.install()
		if len(args) == 0 {
			return
		}
	} else if m.uninstallMode {
		m.uninstall()
		return
	} else {
		var warning bool
		if storeEnabled("system") && !m.checkPlatform() {
			warning = true
			log.Println("Note: the local CA is not installed in the system trust store.")
		}
		if storeEnabled("nss") && hasNSS && CertutilInstallHelp != "" && !m.checkNSS() {
			warning = true
			log.Printf("Note: the local CA is not installed in the %s trust store.", NSSBrowsers)
		}
		if storeEnabled("java") && hasJava && !m.checkJava() {
			warning = true
			log.Println("Note: the local CA is not installed in the Java trust store.")
		}
		if warning {
			log.Println("Run \"simba-cert -install\" for certificates to be trusted automatically ⚠️")
		}
	}

	if m.csrPath != "" {
		m.makeCertFromCSR()
		return
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func (m *simbacert) getCAROOT() string {
	if m.config.Ca.CAROOT != "" {
		return findAbsolutePath(m.config.Ca.CAROOT)
	}
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}
	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "simba-cert")
}

func (m *simbacert) install() {
	if storeEnabled("system") {
		if m.checkPlatform() {
			log.Print("The local CA is already installed in the system trust store! 👍")
		} else {
			if m.installPlatform() {
				log.Print("The local CA is now installed in the system trust store! ⚡️")
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if storeEnabled("nss") && hasNSS {
		if m.checkNSS() {
			log.Printf("The local CA is already installed in the %s trust store! 👍", NSSBrowsers)
		} else {
			if hasCertutil && m.installNSS() {
				log.Printf("The local CA is now installed in the %s trust store (requires browser restart)! 🦊", NSSBrowsers)
			} else if CertutilInstallHelp == "" {
				log.Printf(`Note: %s support is not available on your platform. ℹ️`, NSSBrowsers)
			} else if !hasCertutil {
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s! ⚠️`, NSSBrowsers)
				log.Printf(`Install "certutil" with "%s" and re-run "simba-cert -install" 👈`, CertutilInstallHelp)
			}
		}
	}
	if storeEnabled("java") && hasJava {
		if m.checkJava() {
			log.Println("The local CA is already installed in Java's trust store! 👍")
		} else {
			if hasKeytool {
				m.installJava()
				log.Println("The local CA is now installed in Java's trust store! ☕️")
			} else {
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
			}
		}
	}
	log.Print("")
}

func (m *simbacert) uninstall() {
	if storeEnabled("nss") && hasNSS {
		if hasCertutil {
			m.uninstallNSS()
		} else if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, NSSBrowsers)
			log.Printf(`You can install "certutil" with "%s" and re-run "simba-cert -uninstall" 👈`, CertutilInstallHelp)
			log.Print("")
		}
	}
	if storeEnabled("java") && hasJava {
		if hasKeytool {
			m.uninstallJava()
		} else {
			log.Print("")
			log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
			log.Print("")
		}
	}
	if storeEnabled("system") && m.uninstallPlatform() {
		log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
		log.Print("")
	} else if storeEnabled("nss") && hasCertutil {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", NSSBrowsers)
		log.Print("")
	}
}

func (m *simbacert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func findAbsolutePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	return abs
}

func removeDuplicateValues(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. else we jump on another element.
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and simba-cert is not running as root. The (un)install operation might fail. ⚠️`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}
