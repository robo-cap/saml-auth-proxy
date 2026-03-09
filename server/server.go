package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// MiddlewareComponents encapsulates all middleware components created for a given certificate.
// This structure allows atomic replacement of all middleware when certificates are reloaded.
type MiddlewareComponents struct {
	Middleware      *samlsp.Middleware
	RequestTracker  CookieRequestTracker
	SessionProvider samlsp.SessionProvider
	Proxy           *Proxy
	Config          *Config
	Logger          *zap.Logger
}

const fetchMetadataTimeout = 30 * time.Second

// createMiddleware creates all middleware components for a given certificate.
// This function is called both at startup and during certificate reload.
func createMiddleware(ctx context.Context, listener net.Listener, logger *zap.Logger, cfg *Config, keyPair tls.Certificate) (*MiddlewareComponents, error) {
	privateKey := keyPair.PrivateKey.(*rsa.PrivateKey)

	idpMetadataUrl, err := url.Parse(cfg.IdpMetadataUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IdP metdata URL: %w", err)
	}

	rootUrl, err := url.Parse(cfg.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	httpClient, err := setupHttpClient(cfg.IdpCaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to setup HTTP client: %w", err)
	}

	samlOpts := samlsp.Options{
		URL:               *rootUrl,
		Key:               privateKey,
		Certificate:       keyPair.Leaf,
		AllowIDPInitiated: cfg.AllowIdpInitiated,
		SignRequest:       cfg.SignRequests,
	}
	if cfg.EntityID != "" {
		samlOpts.EntityID = cfg.EntityID
	}

	samlOpts.IDPMetadata, err = fetchMetadata(ctx, httpClient, idpMetadataUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch/load IdP metadata: %w", err)
	}

	middleware, err := samlsp.New(samlOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SP: %w", err)
	}

	switch cfg.NameIdFormat {
	case "unspecified":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	case "transient":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.TransientNameIDFormat
	case "email":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat
	case "persistent":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.PersistentNameIDFormat
	default:
		middleware.ServiceProvider.AuthnNameIDFormat = saml.NameIDFormat(cfg.NameIdFormat)
	}

	var cookieDomain = cfg.CookieDomain
	if cookieDomain == "" {
		cookieDomain = rootUrl.Hostname()
	}
	middleware.RequestTracker = CookieRequestTracker{
		CookieRequestTracker: samlsp.DefaultRequestTracker(samlsp.Options{
			URL: *rootUrl,
			Key: privateKey,
		}, &middleware.ServiceProvider),
		CookieDomain:          cookieDomain,
		StaticRelayState:      cfg.StaticRelayState,
		TrustForwardedHeaders: cfg.AuthVerify,
	}
	cookieSessionProvider := samlsp.DefaultSessionProvider(samlOpts)
	cookieSessionProvider.Name = cfg.CookieName
	cookieSessionProvider.Domain = cookieDomain
	cookieSessionProvider.MaxAge = cfg.CookieMaxAge
	cookieSessionProvider.HTTPOnly = true
	codec := samlsp.DefaultSessionCodec(samlOpts)
	codec.MaxAge = cfg.CookieMaxAge
	cookieSessionProvider.Codec = codec

	if cfg.EncryptJWT {
		jweSessionCodec, err := NewJWESessionCodec(codec, codec.Key.Public(), privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create jwe session codec: %w", err)
		}
		cookieSessionProvider.Codec = jweSessionCodec
	}

	if cfg.InitiateSessionPath != "" {
		middleware.Session = NewInitAnonymousSessionProvider(logger, cfg.InitiateSessionPath, cookieSessionProvider)
	} else {
		middleware.Session = cookieSessionProvider
	}

	proxy, err := NewProxy(logger, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}

	return &MiddlewareComponents{
		Middleware:      middleware,
		RequestTracker:  middleware.RequestTracker.(CookieRequestTracker),
		SessionProvider: cookieSessionProvider,
		Proxy:           proxy,
		Config:          cfg,
		Logger:          logger,
	}, nil
}

// Start starts the SAML auth proxy server with optional certificate reloading.
// If reloadChan is non-nil, the server will listen for new certificates on the channel
// and atomically swap all middleware components when a new certificate is received.
func Start(ctx context.Context, listener net.Listener, logger *zap.Logger, cfg *Config, reloadChan <-chan tls.Certificate) error {
	// Load initial certificate
	keyPair, err := tls.LoadX509KeyPair(cfg.SpCertPath, cfg.SpKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load SP key and certificate: %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse SP certificate: %w", err)
	}

	// Create initial middleware
	components, err := createMiddleware(ctx, listener, logger, cfg, keyPair)
	if err != nil {
		return fmt.Errorf("failed to create middleware: %w", err)
	}

	// Create swapable handlers
	proxy := components.Proxy
	app := http.HandlerFunc(proxy.handler)

	var authVerifyHandler http.Handler
	if cfg.AuthVerify {
		if cfg.AuthVerifyRequireLogin {
			authVerifyHandler = authVerifyWithLogin(logger, proxy, components.Middleware)
		} else {
			authVerifyHandler = authVerify(components.Middleware)
		}
	}

	signInHandler := NewSwapableHandler(http.HandlerFunc(components.Middleware.HandleStartAuthFlow))
	samlHandler := NewSwapableHandler(components.Middleware)
	healthHandler := NewSwapableHandler(http.HandlerFunc(proxy.health))
	rootHandler := NewSwapableHandler(components.Middleware.RequireAccount(app))
	var authVerifySwapHandler *SwapableHandler
	if authVerifyHandler != nil {
		authVerifySwapHandler = NewSwapableHandler(authVerifyHandler)
	}

	// Register handlers
	http.Handle("/saml/sign_in", signInHandler)
	http.Handle("/saml/", samlHandler)
	http.Handle("/_health", healthHandler)
	http.Handle("/", rootHandler)
	if authVerifySwapHandler != nil {
		http.Handle(cfg.AuthVerifyPath, authVerifySwapHandler)
	}

	logger.
		With(zap.String("baseUrl", cfg.BaseUrl)).
		With(zap.String("backendUrl", cfg.BackendUrl)).
		With(zap.String("binding", cfg.Bind)).
		Info("Serving requests")

	// Start certificate reload goroutine if reload channel is provided
	if reloadChan != nil {
		go func() {
			for {
				select {
				case newKeyPair := <-reloadChan:
					logger.Info("Certificate reload triggered")
					newComponents, err := createMiddleware(ctx, listener, logger, cfg, newKeyPair)
					if err != nil {
						logger.Fatal("Failed to reload certificate",
							zap.Error(err),
							zap.String("certPath", cfg.SpCertPath),
							zap.String("keyPath", cfg.SpKeyPath),
						)
					}

					// Swap all handlers atomically
					newProxy := newComponents.Proxy
					newApp := http.HandlerFunc(newProxy.handler)
					signInHandler.Swap(http.HandlerFunc(newComponents.Middleware.HandleStartAuthFlow))
					samlHandler.Swap(newComponents.Middleware)
					healthHandler.Swap(http.HandlerFunc(newProxy.health))
					rootHandler.Swap(newComponents.Middleware.RequireAccount(newApp))
					if authVerifySwapHandler != nil {
						if cfg.AuthVerifyRequireLogin {
							authVerifySwapHandler.Swap(authVerifyWithLogin(logger, newProxy, newComponents.Middleware))
						} else {
							authVerifySwapHandler.Swap(authVerify(newComponents.Middleware))
						}
					}

					logger.Info("Certificate reloaded successfully",
						zap.String("subject", newKeyPair.Leaf.Subject.CommonName),
						zap.Time("notAfter", newKeyPair.Leaf.NotAfter),
					)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	return http.Serve(listener, nil)
}

// StartLegacy starts the server without certificate reloading support.
// This function maintains backward compatibility with the original API.
func StartLegacy(ctx context.Context, listener net.Listener, logger *zap.Logger, cfg *Config) error {
	return Start(ctx, listener, logger, cfg, nil)
}

func fetchMetadata(ctx context.Context, client *http.Client, idpMetadataUrl *url.URL) (*saml.EntityDescriptor, error) {
	if idpMetadataUrl.Scheme == "file" {
		data, err := os.ReadFile(idpMetadataUrl.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read IdP metadata file.: %w", err)
		}
		idpMetadata := &saml.EntityDescriptor{}
		err = xml.Unmarshal(data, idpMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal IdP metadata XML.: %w", err)
		}
		return idpMetadata, nil
	} else {
		reqCtx, _ := context.WithTimeout(ctx, fetchMetadataTimeout)
		return samlsp.FetchMetadata(reqCtx, client, *idpMetadataUrl)
	}
}

func setupHttpClient(idpCaFile string) (*http.Client, error) {
	if idpCaFile == "" {
		return http.DefaultClient, nil
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := os.ReadFile(idpCaFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read IdP CA file: %w", err)
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("INF No certs appended, using system certs only")
	}

	config := &tls.Config{
		RootCAs: rootCAs,
	}

	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	return client, nil
}

func authVerifyWithLogin(logger *zap.Logger, proxy *Proxy, middleware *samlsp.Middleware) http.Handler {
	return middleware.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := samlsp.SessionFromContext(r.Context())

		sessionClaims, ok := session.(samlsp.JWTSessionClaims)
		if !ok {
			logger.Error("session is not expected type")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		proxy.addHeaders(sessionClaims, w.Header()) // pass over SAML attrs as headers

		w.WriteHeader(http.StatusNoContent)
	}))
}

func authVerify(middleware *samlsp.Middleware) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, err := middleware.Session.GetSession(r)

		if session != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if err == samlsp.ErrNoSession {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

	})
}
