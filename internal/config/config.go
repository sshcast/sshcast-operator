package config

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/bcrypt"
)

const (
	OperatorPrivPrefix = "sc_op_priv_"
	OperatorPubPrefix  = "sc_op_pub_"
	DefaultSysconfig   = "/etc/sysconfig/sshcast-operator"
)

type UserEntry struct {
	Username     string `toml:"username" json:"username"`
	PasswordHash string `toml:"password_hash" json:"password_hash"`
}

type Config struct {
	SysconfigPath      string            `toml:"-" name:"sysconfig" default:"/etc/sysconfig/sshcast-operator" help:"Path to /etc/sysconfig/sshcast-operator when SSHCAST_OPERATOR_KEY is not in env." placeholder:"PATH"`
	ListenAddr         string            `toml:"listen_addr" name:"listen" aliases:"listen-addr" default:"unix:/run/sshcast/operator.sock" help:"Listen address override when not socket-activated (e.g. unix:/run/sshcast/operator.sock or 127.0.0.1:8090)."`
	BasePath           string            `toml:"base_path" name:"base-path" default:"/console" help:"Base URL path override (default: /console)."`
	DefaultExpiresDays uint64            `toml:"default_expires_days" name:"default-expires-days" default:"365" help:"Default certificate validity period in days."`
	Users              []UserEntry       `toml:"users" json:"users" name:"users" hidden:""`
	UserPasswords      map[string]string `toml:"user_passwords" json:"user_passwords" name:"user-passwords" hidden:""`

	OperatorPrivKey ed25519.PrivateKey `toml:"-" kong:"-"`
	OperatorPubKey  ed25519.PublicKey  `toml:"-" kong:"-"`
	compiledUsers   map[string]string  `toml:"-" kong:"-"`
}

func Default() *Config {
	return &Config{
		SysconfigPath:      DefaultSysconfig,
		ListenAddr:         "unix:/run/sshcast/operator.sock",
		BasePath:           "/console",
		DefaultExpiresDays: 365,
		compiledUsers:      make(map[string]string),
	}
}

// DefaultPaths returns default operator.toml search paths (such as $CONFIGURATION_DIRECTORY/operator.toml).
func DefaultPaths() []string {
	var paths []string
	if confDir := strings.TrimSpace(os.Getenv("CONFIGURATION_DIRECTORY")); confDir != "" {
		paths = append(paths, filepath.Join(strings.Split(confDir, ":")[0], "operator.toml"))
	}
	paths = append(paths, "/etc/sshcast/operator.toml")
	return paths
}

// TOML returns a Kong Resolver that loads configuration values from a TOML reader using go-toml/v2.
func TOML(r io.Reader) (kong.Resolver, error) {
	values := map[string]any{}
	if err := toml.NewDecoder(r).Decode(&values); err != nil {
		return nil, err
	}
	var f kong.ResolverFunc = func(context *kong.Context, parent *kong.Path, flag *kong.Flag) (any, error) {
		if tomlKey := strings.Split(flag.Tag.Get("toml"), ",")[0]; tomlKey != "" && tomlKey != "-" {
			if raw, ok := values[tomlKey]; ok {
				return raw, nil
			}
		}
		name := strings.ReplaceAll(flag.Name, "-", "_")
		if raw, ok := values[name]; ok {
			return raw, nil
		}
		for _, alias := range flag.Aliases {
			if raw, ok := values[strings.ReplaceAll(alias, "-", "_")]; ok {
				return raw, nil
			}
		}
		return nil, nil
	}
	return f, nil
}

// AfterApply implements kong's post-apply hook to normalize paths and compile user credentials.
func (c *Config) AfterApply() error {
	c.Normalize()
	return nil
}

func Load(path string, sysconfigPath string) (*Config, error) {
	cfg := Default()
	if sysconfigPath != "" {
		cfg.SysconfigPath = sysconfigPath
	}
	if path == "" {
		for _, candidate := range DefaultPaths() {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := toml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	cfg.Normalize()

	if err := cfg.LoadOperatorKey(cfg.SysconfigPath); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Normalize() {
	bp := strings.TrimSpace(c.BasePath)
	if bp == "" || bp == "/" {
		c.BasePath = "/console"
	} else {
		if !strings.HasPrefix(bp, "/") {
			bp = "/" + bp
		}
		c.BasePath = strings.TrimRight(bp, "/")
	}

	c.compiledUsers = make(map[string]string)
	for k, v := range c.UserPasswords {
		u := strings.TrimSpace(k)
		h := strings.TrimSpace(v)
		if u != "" && h != "" {
			c.compiledUsers[u] = h
		}
	}
	for _, entry := range c.Users {
		u := strings.TrimSpace(entry.Username)
		h := strings.TrimSpace(entry.PasswordHash)
		if u != "" && h != "" {
			c.compiledUsers[u] = h
		}
	}
}

func (c *Config) UserCount() int {
	return len(c.compiledUsers)
}

func (c *Config) VerifyPassword(username, password string) bool {
	u := strings.TrimSpace(username)
	if u == "" || password == "" {
		return false
	}
	hashStr, ok := c.compiledUsers[u]
	if !ok || hashStr == "" {
		return false
	}
	return CheckPasswordHash(password, hashStr)
}

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func CheckPasswordHash(password, hashStr string) bool {
	h := strings.TrimSpace(hashStr)
	if strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil
	}
	hexPart := strings.TrimPrefix(h, "sha256:")
	if len(hexPart) == 64 {
		if expected, err := hex.DecodeString(hexPart); err == nil && len(expected) == sha256.Size {
			sum := sha256.Sum256([]byte(password))
			return subtle.ConstantTimeCompare(sum[:], expected) == 1
		}
	}
	return false
}

func GenerateOperatorKeypair() (privToken string, pubToken string, priv ed25519.PrivateKey, pub ed25519.PublicKey, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", nil, nil, err
	}
	seed := priv.Seed()
	privToken = OperatorPrivPrefix + hex.EncodeToString(seed)
	pubToken = OperatorPubPrefix + hex.EncodeToString(pub)
	return privToken, pubToken, priv, pub, nil
}

func ParseOperatorPrivKey(raw string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, `"'`)
	s = strings.TrimPrefix(s, OperatorPrivPrefix)
	s = strings.TrimPrefix(s, "sc_priv_")
	if s == "" {
		return nil, nil, errors.New("operator private key is empty")
	}
	if b, err := hex.DecodeString(s); err == nil {
		switch len(b) {
		case ed25519.SeedSize:
			priv := ed25519.NewKeyFromSeed(b)
			return priv, priv.Public().(ed25519.PublicKey), nil
		case ed25519.PrivateKeySize:
			priv := ed25519.PrivateKey(b)
			return priv, priv.Public().(ed25519.PublicKey), nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			switch len(b) {
			case ed25519.SeedSize:
				priv := ed25519.NewKeyFromSeed(b)
				return priv, priv.Public().(ed25519.PublicKey), nil
			case ed25519.PrivateKeySize:
				priv := ed25519.PrivateKey(b)
				return priv, priv.Public().(ed25519.PublicKey), nil
			}
		}
	}
	return nil, nil, errors.New("invalid Ed25519 operator private key encoding (expected sc_op_priv_<64-hex-seed>, 32-byte seed hex, or base64)")
}

func ParseUserPubKey(raw string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "sc_pub_")
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("invalid 32-byte Ed25519 user public key (expected sc_pub_<64-hex> from sshcast-client keygen)")
}

func ReadOperatorKeyFromEnvOrFile(sysconfigPath string) (string, error) {
	if v := strings.TrimSpace(os.Getenv("SSHCAST_OPERATOR_KEY")); v != "" {
		return v, nil
	}
	if sysconfigPath == "" {
		sysconfigPath = DefaultSysconfig
	}
	data, err := os.ReadFile(sysconfigPath)
	if err != nil {
		return "", fmt.Errorf("SSHCAST_OPERATOR_KEY is not set in environment and failed to read %s: %w", sysconfigPath, err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		if k, v, ok := strings.Cut(line, "="); ok {
			if strings.TrimSpace(k) == "SSHCAST_OPERATOR_KEY" {
				val := strings.Trim(strings.TrimSpace(v), `"'`)
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", fmt.Errorf("SSHCAST_OPERATOR_KEY is empty in %s (run `sshcast-operator --keygen` or `sshcast-operator --init-sysconfig %s`)", sysconfigPath, sysconfigPath)
}

func (c *Config) LoadOperatorKey(sysconfigPath string) error {
	rawKey, err := ReadOperatorKeyFromEnvOrFile(sysconfigPath)
	if err != nil {
		return err
	}
	priv, pub, err := ParseOperatorPrivKey(rawKey)
	if err != nil {
		return err
	}
	c.OperatorPrivKey = priv
	c.OperatorPubKey = pub
	return nil
}

func (c *Config) OperatorPubKeyToken() string {
	if len(c.OperatorPubKey) == 0 {
		return ""
	}
	return OperatorPubPrefix + hex.EncodeToString(c.OperatorPubKey)
}

// InitSysconfigFile ensures that sysconfigPath contains a valid non-empty SSHCAST_OPERATOR_KEY.
// If the file already defines a valid SSHCAST_OPERATOR_KEY, it leaves it untouched and returns (pubToken, false, nil).
// Otherwise, it generates a new Ed25519 operator keypair, writes it with 0600 permissions, and returns (pubToken, true, nil).
func InitSysconfigFile(sysconfigPath string) (string, bool, error) {
	if sysconfigPath == "" {
		sysconfigPath = DefaultSysconfig
	}
	if existing, err := ReadOperatorKeyFromEnvOrFile(sysconfigPath); err == nil {
		if _, pub, err := ParseOperatorPrivKey(existing); err == nil {
			return OperatorPubPrefix + hex.EncodeToString(pub), false, nil
		}
	}
	privToken, pubToken, _, _, err := GenerateOperatorKeypair()
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(sysconfigPath), 0755); err != nil {
		return "", false, err
	}
	content := fmt.Sprintf(`# Sshcast Operator Environment Configuration (/etc/sysconfig/sshcast-operator)
# Loaded by sshcast-operator.service via systemd EnvironmentFile.
#
# Corresponding Operator Public Key for /etc/sshcast/server.toml:
#   trusted_operator_pubkeys = ["%s"]
SSHCAST_OPERATOR_KEY="%s"
`, pubToken, privToken)
	if err := os.WriteFile(sysconfigPath, []byte(content), 0600); err != nil {
		return "", false, err
	}
	return pubToken, true, nil
}
