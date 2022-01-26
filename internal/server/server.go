package server

import (
	"bytes"
	"context"
	"github.com/mylxsw/webdav-server/internal/config"
	"golang.org/x/net/webdav"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/webdav-server/internal/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server interface {
	Start(ctx context.Context, listener net.Listener)
}

type webdavServer struct {
	authSrv  service.AuthService
	resolver infra.Resolver
	log      log.Logger
	handler  *webdav.Handler
}

func New(resolver infra.Resolver, logger log.Logger, handler *webdav.Handler, authSrv service.AuthService) Server {
	server := &webdavServer{log: logger, authSrv: authSrv, resolver: resolver, handler: handler}

	resolver.MustResolve(func(conf *config.Config, userGroupRules *config.UserGroupRules) {
		http.HandleFunc("/", server.buildHandler(conf, userGroupRules))
		http.Handle("/metrics", promhttp.Handler())
	})

	return server
}

func (server *webdavServer) Start(ctx context.Context, listener net.Listener) {
	srv := &http.Server{Handler: http.DefaultServeMux}

	stopped := make(chan interface{})
	go server.resolver.MustResolve(func(conf *config.Config) {
		var err error
		if conf.HTTPS {
			err = srv.ServeTLS(tcpKeepAliveListener{listener.(*net.TCPListener)}, conf.CertFile, conf.KeyFile)
		} else {
			err = srv.Serve(tcpKeepAliveListener{listener.(*net.TCPListener)})
		}
		if err != nil {
			log.Debugf("The http server has stopped: %v", err)

			if err != http.ErrServerClosed {
				panic(err)
			}
		}

		stopped <- struct{}{}
	})

	for {
		select {
		case <-ctx.Done():
			log.Warning("Prepare to shutdown...")
			if err := srv.Shutdown(context.TODO()); err != nil {
				log.Errorf("HTTP webdavServer shutdown failed: %s", err.Error())
			}

			log.Warning("HTTP webdavServer shutdown successful")
			return
		case <-stopped:
			return
		}
	}
}

func (server *webdavServer) buildHandler(conf *config.Config, userGroupRules *config.UserGroupRules) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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

		headers := make(map[string]string)
		for k, v := range r.Header {
			if str.InIgnoreCase(k, []string{"Authorization", "Accept-Language", "Content-Length", "Accept", "Connection", "Accept-Encoding", "Content-Type"}) {
				continue
			}

			headers[k] = strings.Join(v, ", ")
		}

		targetResponse := &responseWriterWrap{
			Headers:    make(http.Header),
			body:       bytes.NewBuffer([]byte{}),
			StatusCode: 0,
		}

		var clientIP string
		if conf.ClientRealIPHeader != "" {
			// 如从请求头 X-Forwarded-For 中获取真实 IP，列表中第一个 IP 为真实的客户端 IP 地址
			clientIP = strings.Split(r.Header.Get(conf.ClientRealIPHeader), ",")[0]
		}

		if clientIP == "" {
			clientIP = strings.Split(r.RemoteAddr, ":")[0]
		}

		readonlyRequest := str.InIgnoreCase(r.Method, []string{"GET", "HEAD", "OPTIONS", "PROPFIND"})
		defer func() {
			resp := targetResponse.RealWrite(w)
			log.F(log.M{
				"readonly": readonlyRequest,
				"remote":   clientIP,
				"user":     user,
				"request": log.M{
					"method":  r.Method,
					"url":     r.RequestURI,
					"headers": headers,
				},
				"response": resp,
			}).Debugf("request")
		}()

		if !user.HasPrivilege(conf, userGroupRules, readonlyRequest, r.URL.Path) {
			log.WithFields(log.Fields{"username": username}).Debugf("access denied: %v", err)
			http.Error(targetResponse, "access denied", http.StatusForbidden)
			return
		}

		if r.Method == "HEAD" {
			w = newResponseWriterNoBody(targetResponse)
		}

		// Excerpt from RFC4918, section 9.4:
		//
		// 		GET, when applied to a collection, may return the contents of an
		//		"index.html" resource, a human-readable view of the contents of
		//		the collection, or something else altogether.
		//
		// Get, when applied to collection, will return the same as PROPFIND method.
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, server.handler.Prefix) {
			info, err := server.handler.FileSystem.Stat(context.TODO(), strings.TrimPrefix(r.URL.Path, server.handler.Prefix))
			if err == nil && info.IsDir() {
				r.Method = "PROPFIND"

				if r.Header.Get("Depth") == "" {
					r.Header.Add("Depth", "1")
				}
			}
		}

		// Runs the WebDAV.
		//u.Handler.LockSystem = webdav.NewMemLS()
		server.handler.ServeHTTP(targetResponse, r)
	}
}

// responseWriterWrap http.ResponseWriter 实现，用于存储代理请求返回数据，避免直接发送给客户端
type responseWriterWrap struct {
	Headers    http.Header
	body       *bytes.Buffer
	Body       []byte
	StatusCode int
}

type response struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
}

func (rw *responseWriterWrap) RealWrite(w http.ResponseWriter) response {
	body := rw.body.Bytes()
	for k, v := range rw.Header() {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if rw.StatusCode > 0 {
		w.WriteHeader(rw.StatusCode)
	}

	_, _ = w.Write(body)

	return response{
		StatusCode: rw.StatusCode,
		Body:       string(body),
	}
}

// Header 实现 http.ResponseWriter 接口
func (rw *responseWriterWrap) Header() http.Header {
	return rw.Headers
}

// Write 实现 http.ResponseWriter 接口
func (rw *responseWriterWrap) Write(bytes []byte) (int, error) {
	return rw.body.Write(bytes)
}

// WriteHeader 实现 http.ResponseWriter 接口
func (rw *responseWriterWrap) WriteHeader(statusCode int) {
	rw.StatusCode = statusCode
}

// responseWriterNoBody is a wrapper used to suppress the body of the response
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
