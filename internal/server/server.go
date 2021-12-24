package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/webdav-server/internal/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	conf     *Config
	authSrv  service.AuthService
	listener net.Listener
	resolver infra.Resolver
	auditLog log.Logger
}

func New(resolver infra.Resolver, conf *Config, authSrv service.AuthService, listener net.Listener) *Server {
	return &Server{conf: conf, authSrv: authSrv, resolver: resolver, listener: listener, auditLog: log.Module("audit")}
}

func (server *Server) Start(ctx context.Context) {
	http.HandleFunc("/", server.ServeHTTP)
	http.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{Handler: http.DefaultServeMux}

	stopped := make(chan interface{})
	go func() {
		if err := srv.Serve(tcpKeepAliveListener{server.listener.(*net.TCPListener)}); err != nil {
			log.Debugf("The http server has stopped: %v", err)

			if err != http.ErrServerClosed {
				panic(err)
			}
		}

		stopped <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Warning("Prepare to shutdown...")
			if err := srv.Shutdown(context.TODO()); err != nil {
				log.Errorf("HTTP Server shutdown failed: %s", err.Error())
			}

			log.Warning("HTTP Server shutdown successful")
			return
		case <-stopped:
			return
		}
	}
}

func (server *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	reqOrigin := r.Header.Get("Origin")
	if server.conf.Cors.Enabled && reqOrigin != "" {
		headers := w.Header()

		allowedHeaders := strings.Join(server.conf.Cors.AllowedHeaders, ", ")
		allowedMethods := strings.Join(server.conf.Cors.AllowedMethods, ", ")
		exposedHeaders := strings.Join(server.conf.Cors.ExposedHeaders, ", ")

		allowAllHosts := len(server.conf.Cors.AllowedHosts) == 1 && server.conf.Cors.AllowedHosts[0] == "*"
		allowedHost := server.isAllowedHost(server.conf.Cors.AllowedHosts, reqOrigin)

		if allowAllHosts {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if allowedHost {
			headers.Set("Access-Control-Allow-Origin", reqOrigin)
		}

		if allowAllHosts || allowedHost {
			headers.Set("Access-Control-Allow-Headers", allowedHeaders)
			headers.Set("Access-Control-Allow-Methods", allowedMethods)

			if server.conf.Cors.Credentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}

			if len(server.conf.Cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
		}
	}

	if r.Method == "OPTIONS" && server.conf.Cors.Enabled && reqOrigin != "" {
		return
	}

	currentUser := server.conf.DefaultUser
	if server.conf.AuthEnabled {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		// Gets the correct user for this request.
		username, password, ok := r.BasicAuth()
		if !ok {
			log.WithFields(log.Fields{"username": username}).Debug("not authorized: no auth header")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		user, err := server.authSrv.Login(username, password)
		if err != nil {
			log.WithFields(log.Fields{"username": username}).Debugf("not authorized: %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		currentUser = authUserToWebdavUser(*user, server.conf)
	} else {
		if username, _, ok := r.BasicAuth(); ok {
			if user, err := server.authSrv.GetUser(username); err == nil {
				currentUser = authUserToWebdavUser(*user, server.conf)
			}
		}
	}

	// Checks for user permissions relatively to this PATH.
	noModification := r.Method == "GET" ||
		r.Method == "HEAD" ||
		r.Method == "OPTIONS" ||
		r.Method == "PROPFIND" ||
		r.Method == "PUT" ||
		r.Method == "LOCK" ||
		r.Method == "UNLOCK" ||
		r.Method == "MOVE" ||
		r.Method == "DELETE"

	if !currentUser.Allowed(r.URL.Path, noModification) {
		log.WithFields(log.Fields{"user": currentUser}).Debugf("user %s not allowed to access %s", currentUser.Username, r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.Method == "HEAD" {
		w = newResponseWriterNoBody(w)
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		if str.InIgnoreCase(k, []string{"Authorization", "Accept-Language", "Content-Length", "Accept", "Connection", "Accept-Encoding", "Content-Type"}) {
			continue
		}

		headers[k] = strings.Join(v, ", ")
	}

	server.auditLog.WithFields(log.Fields{
		"method":  r.Method,
		"url":     r.RequestURI,
		"user":    currentUser.Username,
		"headers": headers,
	}).Infof("%s %s %s", currentUser.Username, r.Method, r.RequestURI)

	// Excerpt from RFC4918, section 9.4:
	//
	// 		GET, when applied to a collection, may return the contents of an
	//		"index.html" resource, a human-readable view of the contents of
	//		the collection, or something else altogether.
	//
	// Get, when applied to collection, will return the same as PROPFIND method.
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, currentUser.Handler.Prefix) {
		info, err := currentUser.Handler.FileSystem.Stat(context.TODO(), strings.TrimPrefix(r.URL.Path, currentUser.Handler.Prefix))
		if err == nil && info.IsDir() {
			r.Method = "PROPFIND"

			if r.Header.Get("Depth") == "" {
				r.Header.Add("Depth", "1")
			}
		}
	}

	// Runs the WebDAV.
	//u.Handler.LockSystem = webdav.NewMemLS()
	currentUser.Handler.ServeHTTP(w, r)
}

func (server *Server) isAllowedHost(allowedHosts []string, origin string) bool {
	for _, host := range allowedHosts {
		if host == origin {
			return true
		}
	}
	return false
}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suppress the body.
func (w responseWriterNoBody) Write([]byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(3 * time.Minute)

	return tc, nil
}
