package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"stingr.net/go/sshcast-operator/internal/config"
	"stingr.net/go/sshcast-operator/internal/db"
	"stingr.net/go/sshcast-operator/internal/web"
)

type cli struct {
	ConfigFile    kong.ConfigFlag `name:"config" help:"Path to operator.toml configuration file (defaults to /etc/sshcast/operator.toml)." placeholder:"PATH"`
	Keygen        bool            `name:"keygen" help:"Generate a new Ed25519 operator keypair and print sysconfig + server.toml snippets."`
	InitSysconfig string          `name:"init-sysconfig" help:"Initialize /etc/sysconfig/sshcast-operator with a new operator key if not yet set." placeholder:"PATH"`
	PrintPubkey   bool            `name:"print-pubkey" help:"Print the active Operator Public Key (sc_op_pub_...)."`
	HashPassword  string          `name:"hash-password" help:"Hash a plaintext password using bcrypt for operator.toml."`
	config.Config `embed:""`
}

// acquireStandaloneListener opens a Unix domain socket (if addr starts with "unix:" or "/")
// or a TCP listener when sshcast-operator is started outside systemd socket activation.
func acquireStandaloneListener(addr string) (net.Listener, error) {
	trimmed := strings.TrimSpace(addr)
	if strings.HasPrefix(trimmed, "unix:") || strings.HasPrefix(trimmed, "/") {
		sockPath := strings.TrimPrefix(trimmed, "unix:")
		if err := os.MkdirAll(filepath.Dir(sockPath), 0755); err != nil {
			return nil, fmt.Errorf("mkdir socket parent %q: %w", filepath.Dir(sockPath), err)
		}
		_ = os.Remove(sockPath)
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			return nil, err
		}
		_ = os.Chmod(sockPath, 0666)
		return ln, nil
	}
	return net.Listen("tcp", trimmed)
}

func main() {
	var cliArgs cli
	kong.Parse(&cliArgs,
		kong.Name("sshcast-operator"),
		kong.Description("Sshcast Operator Console (User Key Signing & Swarm Authority)"),
		kong.Configuration(kongtoml.Loader, config.DefaultPaths()...),
	)

	if cliArgs.Keygen {
		privTok, pubTok, _, _, err := config.GenerateOperatorKeypair()
		if err != nil {
			log.Fatalf("Failed to generate operator keypair: %v", err)
		}
		fmt.Printf("# Put in /etc/sysconfig/sshcast-operator (chmod 0600):\n")
		fmt.Printf("SSHCAST_OPERATOR_KEY=%q\n\n", privTok)
		fmt.Printf("# Put in /etc/sshcast/server.toml on coordinator servers:\n")
		fmt.Printf("trusted_operator_pubkeys = [\n  %q,\n]\n", pubTok)
		return
	}

	if cliArgs.InitSysconfig != "" {
		pubTok, created, err := config.InitSysconfigFile(cliArgs.InitSysconfig)
		if err != nil {
			log.Fatalf("Failed to initialize %s: %v", cliArgs.InitSysconfig, err)
		}
		if created {
			fmt.Printf("Generated new operator key in %s (Public Key: %s)\n", cliArgs.InitSysconfig, pubTok)
		} else {
			fmt.Printf("Existing operator key retained in %s (Public Key: %s)\n", cliArgs.InitSysconfig, pubTok)
		}
		return
	}

	if cliArgs.HashPassword != "" {
		h, err := config.HashPassword(cliArgs.HashPassword)
		if err != nil {
			log.Fatalf("Failed to hash password: %v", err)
		}
		fmt.Println(h)
		return
	}

	if cliArgs.PrintPubkey {
		rawKey, err := config.ReadOperatorKeyFromEnvOrFile(cliArgs.SysconfigPath)
		if err != nil {
			log.Fatalf("Failed to load operator key: %v", err)
		}
		_, pub, err := config.ParseOperatorPrivKey(rawKey)
		if err != nil {
			log.Fatalf("Invalid operator key: %v", err)
		}
		fmt.Printf("%s%x\n", config.OperatorPubPrefix, []byte(pub))
		return
	}

	cfg := &cliArgs.Config
	if err := cfg.LoadOperatorKey(cfg.SysconfigPath); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("[sshcast-operator] Operator Public Key: %s (base_path=%s, configured_users=%d, db_path=%s)",
		cfg.OperatorPubKeyToken(), cfg.BasePath, cfg.UserCount(), cfg.DBPath)

	sqlDB, queries, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open SQLite database %s: %v", cfg.DBPath, err)
	}
	defer func() {
		_ = sqlDB.Close()
	}()

	consoleSrv := web.NewConsoleServer(cfg, queries)
	httpServer := &http.Server{
		Handler:           consoleSrv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	listeners, err := activation.Listeners()
	if err != nil {
		log.Fatalf("Failed to acquire systemd socket-activated listeners: %v", err)
	}
	if len(listeners) == 0 {
		ln, err := acquireStandaloneListener(cfg.ListenAddr)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
		}
		listeners = append(listeners, ln)
	}

	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		if ln == nil {
			continue
		}
		ln := ln
		go func() {
			log.Printf("[sshcast-operator] Listening on %s://%s (serving %s/)", ln.Addr().Network(), ln.Addr().String(), cfg.BasePath)
			errCh <- httpServer.Serve(ln)
		}()
	}

	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("[sshcast-operator] Received signal %v, shutting down...", sig)
		_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[sshcast-operator] Server error: %v", err)
		}
	}
}
