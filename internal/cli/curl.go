package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/evadcmd/kuzl/internal/netguard"
	"github.com/spf13/cobra"
)

const (
	// maxShowBytes caps what curl writes to stdout, headers included, so that
	// one response can't fill the caller's context.
	maxShowBytes = 100000
	// maxCountBytes is how far past maxShowBytes a body is read to say how
	// much was left out, when its length isn't known up front.
	maxCountBytes = 100 << 20
	// defaultMaxRedirs is kuzl's --max-redirs; curl's is 50.
	defaultMaxRedirs = 10
)

// hasScheme matches a URL that starts with a scheme (RFC 3986) and "://".
var hasScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// curl's exit codes for the failures kuzl reports.
const (
	exitURLMalformat     = 3
	exitCouldntResolve   = 6
	exitCouldntConnect   = 7
	exitHTTPReturned     = 22
	exitWriteError       = 23
	exitTimeout          = 28
	exitSSLConnect       = 35
	exitTooManyRedirects = 47
	exitRecvError        = 56
	exitPeerFailed       = 60
)

// refusedFlags are curl flags kuzl declines, with the reason it gives. They
// are defined, hidden, so that the caller gets the reason rather than
// "unknown flag", and so that a value after one isn't taken for the URL.
var refusedFlags = []struct {
	name, short string
	takesValue  bool
	reason      string
}{
	{"data", "d", true, "kuzl only sends GET and HEAD"},
	{"data-ascii", "", true, "kuzl only sends GET and HEAD"},
	{"data-binary", "", true, "kuzl only sends GET and HEAD"},
	{"data-raw", "", true, "kuzl only sends GET and HEAD"},
	{"data-urlencode", "", true, "kuzl only sends GET and HEAD"},
	{"json", "", true, "kuzl only sends GET and HEAD"},
	{"form", "F", true, "kuzl only sends GET and HEAD"},
	{"form-string", "", true, "kuzl only sends GET and HEAD"},
	{"upload-file", "T", true, "kuzl only sends GET and HEAD"},
	{"config", "K", true, "kuzl reads no config file"},
	{"user", "u", true, `set the header instead, as in -H "Authorization: Basic ..."`},
	{"cookie", "b", true, `kuzl reads no cookie file; set the header instead, as in -H "Cookie: name=value"`},
	{"cookie-jar", "c", true, "kuzl writes no cookie file"},
	{"netrc", "n", false, "kuzl reads no netrc file"},
	{"netrc-file", "", true, "kuzl reads no netrc file"},
	{"netrc-optional", "", false, "kuzl reads no netrc file"},
	{"proxy", "x", true, "kuzl connects directly: through a proxy, its address check would only see the proxy's"},
	{"insecure", "k", false, "kuzl always verifies certificates"},
	{"unix-socket", "", true, "kuzl only connects to public addresses"},
	{"abstract-unix-socket", "", true, "kuzl only connects to public addresses"},
	{"resolve", "", true, "kuzl resolves names itself, so that the address it checks is the one it connects to"},
	{"connect-to", "", true, "kuzl resolves names itself, so that the address it checks is the one it connects to"},
	{"location-trusted", "", false, "kuzl never sends credentials to another origin on a redirect"},
}

// curlFlags are the flags curl takes.
type curlFlags struct {
	silent, showError    bool
	fail, failWithBody   bool
	location             bool
	maxRedirs            int
	head, include        bool
	request              string
	headers              []string
	userAgent, referer   *string // nil if not set
	maxTime, connTimeout float64
	compressed           bool
}

func newCurlCmd(s IO, rec *record) *cobra.Command {
	cmd := newRoot("curl", "Fetch a URL with GET or HEAD", s)
	cmd.Use = "curl [flags] <url>"
	cmd.Long = `Fetch a URL with GET or HEAD and write the response body to stdout.

Only http and https are fetched, and only from the hosts and public
addresses this build allows; a URL without a scheme is http. Nothing local
is ever sent: flags that send data or read a file, such as -d, -F, -T, -K,
-b and -u, are refused with the reason.

Stdout stops after 100000 bytes, headers included, with a note on stderr.
A body that isn't UTF-8 text is not written to stdout.

Errors are curl's: "curl: (N) message" on stderr and exit code N, such as 6
(couldn't resolve), 7 (couldn't connect), 22 (-f and HTTP >= 400), 28
(timeout) and 47 (too many redirects). A refused request exits 2 with the
reason, even with -s.`
	cmd.Args = func(c *cobra.Command, args []string) error {
		if len(args) > 1 {
			return &usageError{err: fmt.Errorf("expected one URL, got %d", len(args)), cmdPath: c.CommandPath()}
		}
		return nil
	}
	// curl's version flag is -V; cobra's default would take -v, which is
	// curl's --verbose. cobra uses a version flag that is already defined.
	cmd.Flags().BoolP("version", "V", false, "version for curl")

	var f curlFlags
	fl := cmd.Flags()
	fl.BoolVarP(&f.silent, "silent", "s", false, "Don't print error messages")
	fl.BoolVarP(&f.showError, "show-error", "S", false, "Print error messages even with -s")
	fl.BoolVarP(&f.fail, "fail", "f", false, "Fail with exit code 22 and no output on HTTP errors (>= 400)")
	fl.BoolVar(&f.failWithBody, "fail-with-body", false, "Fail with exit code 22 on HTTP errors, after writing the response")
	fl.BoolVarP(&f.location, "location", "L", false, "Follow redirects")
	fl.IntVar(&f.maxRedirs, "max-redirs", defaultMaxRedirs, "Follow at most `num` redirects with -L; -1 for no limit")
	fl.BoolVarP(&f.head, "head", "I", false, "Send HEAD and write the response headers")
	fl.BoolVarP(&f.include, "include", "i", false, "Write the response headers before the body")
	fl.StringVarP(&f.request, "request", "X", "", "Request `method`: GET or HEAD")
	fl.StringArrayVarP(&f.headers, "header", "H", nil, `Add a request header, "Name: value"; "Name:" removes one, "Name;" sends it empty`)
	userAgent := fl.StringP("user-agent", "A", "", "User-Agent `name`; empty sends none")
	referer := fl.StringP("referer", "e", "", "Referer `URL`")
	fl.Float64VarP(&f.maxTime, "max-time", "m", 0, "Give up after `seconds` in all")
	fl.Float64Var(&f.connTimeout, "connect-timeout", 0, "Give up connecting after `seconds`")
	fl.BoolVar(&f.compressed, "compressed", false, "Ask for a compressed response (always done; kept for curl's command lines)")
	for _, r := range refusedFlags {
		if r.takesValue {
			fl.StringP(r.name, r.short, "", "")
		} else {
			fl.BoolP(r.name, r.short, false, "")
		}
		_ = fl.MarkHidden(r.name)
	}

	cmd.RunE = func(c *cobra.Command, args []string) error {
		for _, r := range refusedFlags {
			if fl.Changed(r.name) {
				return &refusalError{err: fmt.Errorf("%s is not supported: %s", flagName(r.name, r.short), r.reason)}
			}
		}
		if m := f.request; m != "" && m != http.MethodGet && m != http.MethodHead {
			return &refusalError{err: fmt.Errorf("-X %s is not supported: kuzl only sends GET and HEAD", m)}
		}
		if len(args) == 0 {
			return c.Help()
		}
		if fl.Changed("user-agent") {
			f.userAgent = userAgent
		}
		if fl.Changed("referer") {
			f.referer = referer
		}
		req, err := f.newRequest(c, args[0])
		if err != nil {
			return err
		}
		rec.add("host", req.URL.Hostname(), "method", req.Method)
		return f.fetch(c.Context(), s, req, rec)
	}
	return cmd
}

func flagName(name, short string) string {
	if short == "" {
		return "--" + name
	}
	return "-" + short + "/--" + name
}

// newRequest checks the flags and builds the request they describe. It
// doesn't check the URL against the policy: the client does, for every hop.
func (f *curlFlags) newRequest(c *cobra.Command, rawURL string) (*http.Request, error) {
	usage := func(format string, args ...any) error {
		return &usageError{err: fmt.Errorf(format, args...), cmdPath: c.CommandPath()}
	}
	method := http.MethodGet
	if f.head {
		method = http.MethodHead
	}
	// RunE has refused any other -X.
	if f.request != "" {
		if f.head && f.request != http.MethodHead {
			return nil, usage("-I sends HEAD, not -X %s", f.request)
		}
		method = f.request
	}
	if f.fail && f.failWithBody {
		return nil, usage("use -f or --fail-with-body, not both")
	}
	if f.maxRedirs < -1 {
		return nil, usage("--max-redirs %d: want -1 (no limit) or more", f.maxRedirs)
	}
	if f.maxTime < 0 || f.connTimeout < 0 {
		return nil, usage("a timeout can't be negative")
	}

	// curl takes a URL without a scheme as http. Only a scheme at the start
	// counts: "://" in a query (?next=https://…) isn't one.
	if !hasScheme.MatchString(rawURL) {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return nil, &curlError{code: exitURLMalformat, err: fmt.Errorf("URL rejected: %w", err), quiet: f.quiet()}
	}
	u.Fragment, u.RawFragment = "", ""
	req, err := http.NewRequest(method, u.String(), http.NoBody)
	if err != nil {
		return nil, &curlError{code: exitURLMalformat, err: fmt.Errorf("URL rejected: %w", err), quiet: f.quiet()}
	}

	// As curl does, Accept: */* and its own User-Agent; -A, -e and -H
	// replace them, -H last.
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "kuzl/"+version)
	if f.userAgent != nil {
		// An empty User-Agent header makes Go's client send none.
		req.Header.Set("User-Agent", *f.userAgent)
	}
	if f.referer != nil {
		req.Header.Set("Referer", *f.referer)
	}
	set := map[string]bool{}
	for _, h := range f.headers {
		name, value, remove, err := parseHeader(h)
		if err != nil {
			if _, ok := errors.AsType[*refusalError](err); ok {
				return nil, err
			}
			return nil, usage("%v", err)
		}
		key := http.CanonicalHeaderKey(name)
		switch {
		case remove && key == "User-Agent":
			req.Header.Set(key, "")
		case remove:
			req.Header.Del(key)
		case set[key]:
			req.Header[key] = append(req.Header[key], value)
		default:
			req.Header[key] = []string{value}
			set[key] = true
		}
	}
	return req, nil
}

// parseHeader parses an -H value as curl does: "Name: value" sets a header,
// "Name:" removes it and "Name;" sends it with an empty value.
func parseHeader(h string) (name, value string, remove bool, err error) {
	if strings.HasPrefix(h, "@") {
		return "", "", false, &refusalError{err: errors.New("-H @file is not supported: kuzl reads no local files")}
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		name, value = h[:i], strings.Trim(h[i+1:], " \t")
		remove = value == ""
	} else if n, ok := strings.CutSuffix(h, ";"); ok {
		name = n
	} else {
		return "", "", false, fmt.Errorf(`-H %q is not a header: want "Name: value"`, h)
	}
	if !validHeaderName(name) {
		return "", "", false, fmt.Errorf("-H %q: %q is not a header name", h, name)
	}
	if strings.ContainsFunc(value, func(r rune) bool { return (r < ' ' && r != '\t') || r == 0x7f }) {
		return "", "", false, fmt.Errorf("-H %q: a header value can't hold control characters", h)
	}
	// A Host header other than the URL's would send the request to a host
	// the policy never saw.
	if strings.EqualFold(name, "Host") {
		return "", "", false, &refusalError{err: errors.New("-H Host is not supported: the request goes to the URL's host")}
	}
	return name, value, remove, nil
}

// validHeaderName reports whether s is an HTTP token (RFC 9110).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

func (f *curlFlags) quiet() bool { return f.silent && !f.showError }

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// fetch sends req and writes the response: the headers of every hop with -i
// or -I, then the body, capped at maxShowBytes.
func (f *curlFlags) fetch(ctx context.Context, s IO, req *http.Request, rec *record) error {
	if f.maxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, seconds(f.maxTime))
		defer cancel()
	}
	client, err := s.client(netguard.Options{
		FollowRedirects: f.location,
		MaxRedirects:    f.maxRedirs,
		ConnectTimeout:  seconds(f.connTimeout),
	})
	if err != nil {
		return err
	}
	hops := &hopRecorder{next: client.Transport}
	client.Transport = hops

	start := time.Now()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return f.transferError(err, time.Since(start))
	}
	defer func() { _ = resp.Body.Close() }()
	rec.add("status", resp.StatusCode)

	failed := resp.StatusCode >= 400 && (f.fail || f.failWithBody)
	httpErr := &curlError{
		code:  exitHTTPReturned,
		err:   fmt.Errorf("The requested URL returned error: %d", resp.StatusCode), //nolint:staticcheck // ST1005: curl's message.
		quiet: f.quiet(),
	}
	if failed && f.fail {
		return httpErr
	}

	var head []byte
	if f.head || f.include {
		var b bytes.Buffer
		for _, h := range hops.hops {
			writeHeaders(&b, h)
		}
		head = b.Bytes()
	}
	var body []byte
	var bodyErr error
	more, moreExact := int64(0), true
	if req.Method != http.MethodHead {
		limit := max(maxShowBytes+1-len(head), 0)
		body, bodyErr = io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
		if bodyErr == nil && len(body) == limit {
			more, moreExact, bodyErr = countRest(resp, int64(len(body)))
		}
		rec.add("bytes", int64(len(body))+more)
	}

	data := append(head, body...)
	n := capAt(data, maxShowBytes)
	if shown := data[min(len(head), n):n]; bytes.IndexByte(shown, 0) >= 0 || !utf8.Valid(shown) {
		if _, err := s.Out.Write(data[:min(len(head), n)]); err != nil {
			return f.writeError(err)
		}
		// The failed request matters more to the caller than the binary body.
		if failed {
			return httpErr
		}
		what := "binary output"
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			what += " (Content-Type " + ct + ")"
		}
		return &curlError{code: exitWriteError, err: fmt.Errorf("%s is not written to stdout", what)}
	}
	if _, err := s.Out.Write(data[:n]); err != nil {
		return f.writeError(err)
	}
	if left := int64(len(data)-n) + more; left > 0 {
		if moreExact {
			_, _ = fmt.Fprintf(s.ErrOut, "… truncated, %d more bytes\n", left)
		} else {
			_, _ = fmt.Fprintf(s.ErrOut, "… truncated, more than %d more bytes\n", left)
		}
	}
	if bodyErr != nil {
		return f.transferError(bodyErr, time.Since(start))
	}
	if failed {
		return httpErr
	}
	return nil
}

// countRest returns how many bytes of resp's body are left after the first
// read ones. Its Content-Length says so without reading them, unless Go's
// client decompressed the body; otherwise the rest is read, up to
// maxCountBytes, and exact is false if there was more.
func countRest(resp *http.Response, read int64) (n int64, exact bool, err error) {
	if resp.ContentLength >= read && !resp.Uncompressed {
		return resp.ContentLength - read, true, nil
	}
	n, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCountBytes+1))
	return min(n, maxCountBytes), n <= maxCountBytes, err
}

// capAt returns how much of data to show: all of it, or up to limit bytes, cut
// at a character boundary. A rune is at most utf8.UTFMax bytes, so it backs
// off at most that far; data that isn't UTF-8 is cut at limit.
func capAt(data []byte, limit int) int {
	n := len(data)
	if n > limit {
		n = limit
		for i := 0; i < utf8.UTFMax-1 && n > 0 && !utf8.RuneStart(data[n]); i++ {
			n--
		}
	}
	return n
}

// writeHeaders writes a response's status line and headers as curl -i does,
// with CRLF line ends and a blank line after them. Go keeps headers in a map,
// so they come sorted by name rather than in the server's order.
func writeHeaders(b *bytes.Buffer, resp *http.Response) {
	if resp.ProtoMajor == 2 {
		_, _ = fmt.Fprintf(b, "HTTP/2 %d\r\n", resp.StatusCode)
	} else {
		_, _ = fmt.Fprintf(b, "%s %s\r\n", resp.Proto, resp.Status)
	}
	for _, k := range slices.Sorted(maps.Keys(resp.Header)) {
		for _, v := range resp.Header[k] {
			_, _ = fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
}

// hopRecorder keeps every response the client gets, redirects included, so
// that -i and -I can write each hop's headers, as curl -L does.
type hopRecorder struct {
	next http.RoundTripper
	hops []*http.Response
}

func (r *hopRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err == nil {
		r.hops = append(r.hops, resp)
	}
	return resp, err
}

// transferError maps a failed request to curl's exit code and message. A
// request the policy refuses is a refusalError instead, which -s doesn't
// silence.
// writeError is curl's exit 23 for stdout that can't be written, such as a
// closed pipe.
func (f *curlFlags) writeError(err error) error {
	return &curlError{
		code:  exitWriteError,
		err:   fmt.Errorf("Failure writing output to destination: %w", err), //nolint:staticcheck // ST1005: curl's message.
		quiet: f.quiet(),
	}
}

func (f *curlFlags) transferError(err error, elapsed time.Duration) error {
	if re, ok := errors.AsType[*netguard.RefusedError](err); ok {
		return &refusalError{err: re}
	}
	// *url.Error quotes the URL, query and all; curl's messages don't.
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	code, msg := curlFailure(err, f.maxTime > 0, elapsed)
	return &curlError{code: code, err: errors.New(msg), quiet: f.quiet()}
}

// curlFailure is curl's exit code and message for err.
func curlFailure(err error, maxTime bool, elapsed time.Duration) (int, string) {
	if e, ok := errors.AsType[*netguard.TooManyRedirectsError](err); ok {
		return exitTooManyRedirects, fmt.Sprintf("Maximum (%d) redirects followed", e.Max)
	}
	if errors.Is(err, context.DeadlineExceeded) && maxTime {
		return exitTimeout, fmt.Sprintf("Operation timed out after %d milliseconds", elapsed.Milliseconds())
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return exitTimeout, fmt.Sprintf("Connection timed out after %d milliseconds", elapsed.Milliseconds())
	}
	if e, ok := errors.AsType[*net.DNSError](err); ok {
		return exitCouldntResolve, "Could not resolve host: " + e.Name
	}
	if e, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return exitPeerFailed, fmt.Sprintf("SSL certificate problem: %v", e.Err)
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return exitSSLConnect, fmt.Sprintf("SSL connect error: %v", err)
	}
	if _, ok := errors.AsType[tls.AlertError](err); ok {
		return exitSSLConnect, fmt.Sprintf("SSL connect error: %v", err)
	}
	if e, ok := errors.AsType[*net.OpError](err); ok && e.Op == "dial" {
		return exitCouldntConnect, fmt.Sprintf("Failed to connect: %v", e.Err)
	}
	return exitRecvError, fmt.Sprintf("Failure when receiving data from the peer: %v", err)
}
