package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const debounceDelay = 1 * time.Second

// StartCertReloader watches the SAML certificate and key files for changes
// and sends valid new certificates on the reload channel.
// Returns an error if initial certificate validation fails or if watching fails.
// Per requirements, any reload failure causes the server to crash.
func StartCertReloader(ctx context.Context, logger *zap.Logger, cfg *Config, reloadChan chan<- tls.Certificate) error {
	// Validate initial certificate before starting watcher
	if err := validateCertificate(cfg.SpCertPath, cfg.SpKeyPath); err != nil {
		return fmt.Errorf("initial certificate validation failed: %w", err)
	}

	// Resolve symlinks to get actual file paths
	certPath, err := filepath.EvalSymlinks(cfg.SpCertPath)
	if err != nil {
		return fmt.Errorf("failed to resolve certificate path: %w", err)
	}

	keyPath, err := filepath.EvalSymlinks(cfg.SpKeyPath)
	if err != nil {
		return fmt.Errorf("failed to resolve key path: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Watch the directory containing the cert files to handle symlink rotation
	certDir := filepath.Dir(certPath)
	keyDir := filepath.Dir(keyPath)

	if err := watcher.Add(certDir); err != nil {
		return fmt.Errorf("failed to watch certificate directory %s: %w", certDir, err)
	}

	if certDir != keyDir {
		if err := watcher.Add(keyDir); err != nil {
			return fmt.Errorf("failed to watch key directory %s: %w", keyDir, err)
		}
	}

	logger.Info("Certificate watcher started",
		zap.String("certPath", cfg.SpCertPath),
		zap.String("keyPath", cfg.SpKeyPath),
		zap.String("watchingCertDir", certDir),
		zap.String("watchingKeyDir", keyDir),
	)

	// Use a mutex to protect reload state
	var reloadMu sync.Mutex
	var reloadTimer *time.Timer

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Check if the event is for our certificate or key files
				matchesCert := event.Name == certPath || event.Name == keyPath
				matchesOriginal := event.Name == cfg.SpCertPath || event.Name == cfg.SpKeyPath

				if matchesCert || matchesOriginal {
					// Debounce: reset timer on each event
					reloadMu.Lock()
					if reloadTimer != nil {
						reloadTimer.Stop()
					}
					reloadTimer = time.AfterFunc(debounceDelay, func() {
						reloadMu.Lock()
						defer reloadMu.Unlock()

						logger.Info("Certificate file change detected, attempting reload",
							zap.String("file", event.Name),
						)

						newKeyPair, err := loadAndValidateCertificate(cfg.SpCertPath, cfg.SpKeyPath)
						if err != nil {
							// Per requirements, crash on reload failure
							logger.Error("Certificate reload failed - shutting down",
								zap.Error(err),
								zap.String("certPath", cfg.SpCertPath),
								zap.String("keyPath", cfg.SpKeyPath),
							)
							// Cancel context to trigger errgroup failure
							// This is a bit of a hack but we need to signal the main goroutine
							panic(fmt.Sprintf("certificate reload failed: %v", err))
						}

						// Send on channel - this will block if the server isn't ready
						// but that's fine, it means the server is shutting down
						select {
						case reloadChan <- newKeyPair:
							logger.Info("Certificate reloaded successfully",
								zap.String("subject", newKeyPair.Leaf.Subject.CommonName),
								zap.Time("notAfter", newKeyPair.Leaf.NotAfter),
								zap.Time("expiry", newKeyPair.Leaf.NotAfter),
							)
						case <-ctx.Done():
							return
						}
					})
					reloadMu.Unlock()
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error("Watcher error", zap.Error(err))
				// Per requirements, crash on watcher errors
				panic(fmt.Sprintf("file watcher error: %v", err))

			case <-ctx.Done():
				// Stop any pending reload timer
				reloadMu.Lock()
				if reloadTimer != nil {
					reloadTimer.Stop()
				}
				reloadMu.Unlock()
				return
			}
		}
	}()

	return nil
}

// validateCertificate checks that a certificate and key file form a valid pair
// and that the certificate has not expired and has at least 1 hour of validity remaining
func validateCertificate(certPath, keyPath string) error {
	_, err := loadAndValidateCertificate(certPath, keyPath)
	if err != nil {
		return err
	}
	return nil
}

// loadAndValidateCertificate loads a certificate and key pair, validates them,
// and returns the tls.Certificate
func loadAndValidateCertificate(certPath, keyPath string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate pair: %w", err)
	}

	// Parse the leaf certificate
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()

	// Check if certificate is already expired
	if now.After(keyPair.Leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate is expired: expired at %s", keyPair.Leaf.NotAfter)
	}

	// Check if certificate is not yet valid
	if now.Before(keyPair.Leaf.NotBefore) {
		return tls.Certificate{}, fmt.Errorf("certificate is not yet valid: valid from %s", keyPair.Leaf.NotBefore)
	}

	// Check if certificate has at least 1 hour of validity remaining
	minExpiry := now.Add(1 * time.Hour)
	if minExpiry.After(keyPair.Leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate expires too soon: expires at %s (need at least 1 hour)", keyPair.Leaf.NotAfter)
	}

	// Verify the private key matches the certificate
	switch privKey := keyPair.PrivateKey.(type) {
	case interface{ Public() any }:
		// Most key types implement Public()
		pubKey := privKey.Public()
		if !keysMatch(pubKey, keyPair.Leaf.PublicKey) {
			return tls.Certificate{}, errors.New("certificate and private key do not match")
		}
	}

	return keyPair, nil
}

// keysMatch checks if a public key matches a certificate's public key
func keysMatch(pubKey1, pubKey2 any) bool {
	// Simple comparison - for RSA keys we can compare the moduli
	// This is a basic check; for production you might want more thorough validation
	return fmt.Sprintf("%v", pubKey1) == fmt.Sprintf("%v", pubKey2)
}
