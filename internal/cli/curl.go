package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/evadcmd/kuzl/internal/netguard"
	"github.com/evadcmd/kuzl/internal/workspace"
	"github.com/spf13/cobra"
)

const (
	// maxShowBytes caps what curl writes to stdout, headers included, so that
	// one response can't fill the caller's context.
	maxShowBytes = 100000
	// maxCountBytes is how far past maxShowBytes a body is read to say how
	// much was left out, when its length isn't known up front.
	maxCountBytes = 100 << 20
	// maxDownloadBytes caps the body -o writes, and --max-filesize.
	maxDownloadBytes = 100 << 20
	// defaultMaxRedirs is kuzl's --max-redirs; curl's is 50.
	defaultMaxRedirs = 10
)

var (
	// hasScheme matches a URL that starts with a scheme (RFC 3986) and "://".
	hasScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	// validRange matches an -r value: byte ranges as in 0-499, 500- or -500,
	// separated by commas.
	validRange = regexp.MustCompile(`^(\d+-\d*|-\d+)(,(\d+-\d*|-\d+))*$`)
)

// writeOutNames are the -w variables kuzl knows.
var writeOutNames = []string{"http_code", "content_type", "url_effective", "size_download"}

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
	exitFileSizeExceeded = 63
)

// refusedFlags are curl flags kuzl declines, with the reason it gives. They
// are defined, hidden, so that the caller gets the reason rather than
// "unknown flag", and so that a value after one isn't taken for the URL.
var refusedFlags = []struct {
	name, short string
	takesValue  bool
	reason      string
}{
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

// dataFlags are curl's flags that send data. kuzl takes them only with -G,
// which puts the data in the query string instead of a request body.
var dataFlags = []struct {
	name, short, usage string
}{
	{"data", "d", "With -G, add `data` to the query string, already encoded"},
	{"data-ascii", "", "With -G, add `data` as -d does"},
	{"data-binary", "", "With -G, add `data` as -d does"},
	{"data-raw", "", "With -G, add `data` as -d does, with @ not special"},
	{"data-urlencode", "", "With -G, add `data` to the query string URL-encoded: content, =content or name=content"},
}

// dataArg is one value of a data flag.
type dataArg struct {
	name, short string // the flag's
	value       string
}

// dataValue is the pflag.Value of a data flag. They all append to one list, so
// that the values keep the command line's order, as curl's do.
type dataValue struct {
	name, short string
	list        *[]dataArg
}

func (d *dataValue) String() string { return "" }
func (d *dataValue) Type() string   { return "string" }
func (d *dataValue) Set(s string) error {
	*d.list = append(*d.list, dataArg{d.name, d.short, s})
	return nil
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
	output               string
	remoteName           bool
	createDirs           bool
	maxFilesize          string
	rangeSpec            string
	writeOut             string
	get                  bool
	data                 []dataArg

	query string // the query -G builds from data; set by RunE

	// Set by newRequest from the flags above.
	outFile  string // the file -o or -O names; "" for stdout
	maxBytes int64  // --max-filesize; 0 if not set
}

func newCurlCmd(s IO, rec *record) *cobra.Command {
	cmd := newRoot("curl", "Fetch a URL with GET or HEAD", s)
	cmd.Use = "curl [flags] <url>"
	cmd.Long = `Fetch a URL with GET or HEAD and write the response body to stdout.

Only http and https are fetched, and only from the hosts and public
addresses this build allows; a URL without a scheme is http. Nothing local
is ever sent: flags that send data or read a file, such as -F, -T, -K, -b
and -u, are refused with the reason. -d and --data-urlencode are taken only
with -G, which puts them in the query string, and never read a file.

Stdout stops after 100000 bytes, headers included, with a note on stderr.
A body that isn't UTF-8 text is not written to stdout. -o and -O write the
response to a file instead, up to 100 MiB, and only inside $KUZL_ROOT (the
working directory if unset).

Errors are curl's: "curl: (N) message" on stderr and exit code N, such as 6
(couldn't resolve), 7 (couldn't connect), 22 (-f and HTTP >= 400), 28
(timeout), 47 (too many redirects) and 63 (--max-filesize). A refused
request exits 2 with the reason, even with -s.`
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
	fl.StringVarP(&f.output, "output", "o", "", "Write to `file` instead of stdout, inside $KUZL_ROOT; - is stdout")
	fl.BoolVarP(&f.remoteName, "remote-name", "O", false, "Write to a file named as the URL's last path segment")
	fl.BoolVar(&f.createDirs, "create-dirs", false, "Create the directories -o needs (always done; kept for curl's command lines)")
	fl.StringVar(&f.maxFilesize, "max-filesize", "", "Fail with exit code 63 on a body over `bytes` (k, M and G suffixes); at most 100M, the default with -o")
	fl.StringVarP(&f.rangeSpec, "range", "r", "", "Ask for these byte `ranges` only, as in 0-499, 500- or -500")
	fl.StringVarP(&f.writeOut, "write-out", "w", "", "Write `format` to stdout after the transfer, with %{http_code}, %{content_type}, %{url_effective} and %{size_download}")
	fl.BoolVarP(&f.get, "get", "G", false, "Put the -d and --data-urlencode data in the query string; they are refused without -G")
	for _, d := range dataFlags {
		fl.VarP(&dataValue{name: d.name, short: d.short, list: &f.data}, d.name, d.short, d.usage)
	}
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
		if len(f.data) > 0 && !f.get {
			d := f.data[0]
			return &refusalError{err: fmt.Errorf("%s without -G is not supported: kuzl only sends GET and HEAD; -G puts the data in the query string", flagName(d.name, d.short))}
		}
		var err error
		if f.query, err = queryData(f.data); err != nil {
			return err
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
		// A file outside the root is refused before anything is sent.
		var root *workspace.Root
		if f.outFile != "" {
			if root, err = s.root(); err != nil {
				return err
			}
			defer func() { _ = root.Close() }()
			if err := root.Check(f.outFile); err != nil {
				return &refusalError{err: fmt.Errorf("%s %w", outFlag(f.remoteName), err)}
			}
		}
		rec.add("host", req.URL.Hostname(), "method", req.Method)
		return f.fetch(c.Context(), s, req, root, rec)
	}
	return cmd
}

// outFlag names the flag that set the output file, for messages.
func outFlag(remoteName bool) string {
	if remoteName {
		return "-O"
	}
	return "-o"
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
	// An empty -o, such as an unset shell variable, would otherwise look like
	// no -o and send the body to stdout.
	if c.Flags().Changed("output") && f.output == "" {
		return nil, usage(`-o "": want a file name, or - for stdout`)
	}
	if f.output != "" && f.remoteName {
		return nil, usage("use -o or -O, not both")
	}
	if c.Flags().Changed("max-filesize") {
		n, ok := parseSize(f.maxFilesize)
		if !ok {
			return nil, usage("--max-filesize %q: want a number of bytes, with k, M or G or without", f.maxFilesize)
		}
		if n > maxDownloadBytes {
			return nil, usage("--max-filesize %s: kuzl downloads at most 100M", f.maxFilesize)
		}
		f.maxBytes = n
	}
	if f.rangeSpec != "" && !validRange.MatchString(f.rangeSpec) {
		return nil, usage("-r %q: want byte ranges, as in 0-499, 500- or -500", f.rangeSpec)
	}
	if strings.HasPrefix(f.writeOut, "@") {
		return nil, &refusalError{err: errors.New("-w @file is not supported: kuzl reads no local files")}
	}
	if _, err := expandWriteOut(f.writeOut, nil); err != nil {
		return nil, usage("-w: %v", err)
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
	// -G adds its data after the URL's own query, as curl does.
	if f.query != "" {
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += f.query
	}
	req, err := http.NewRequest(method, u.String(), http.NoBody)
	if err != nil {
		return nil, &curlError{code: exitURLMalformat, err: fmt.Errorf("URL rejected: %w", err), quiet: f.quiet()}
	}

	switch {
	case f.remoteName:
		// As curl does, the URL as given names the file, not the one a
		// redirect leads to, and it isn't decoded: %2F stays in the name.
		p := u.EscapedPath()
		f.outFile = p[strings.LastIndexByte(p, '/')+1:]
		if f.outFile == "" {
			return nil, &curlError{code: exitWriteError, err: errors.New("Remote file name has no length"), quiet: f.quiet()} //nolint:staticcheck // ST1005: curl's message.
		}
	case f.output != "-":
		f.outFile = f.output
	}

	// As curl does, Accept: */* and its own User-Agent; -A, -e, -r and -H
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
	if f.rangeSpec != "" {
		req.Header.Set("Range", "bytes="+f.rangeSpec)
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

// queryData builds the query string of -G from the data flags' values as curl
// does: joined with &, -d's as given and --data-urlencode's URL-encoded. A
// value that would read a file, as -d @file does, is refused; --data-raw
// takes @ as is, as curl does.
func queryData(data []dataArg) (string, error) {
	parts := make([]string, 0, len(data))
	for _, d := range data {
		switch {
		case d.name == "data-urlencode":
			p, err := urlencodeData(d.value)
			if err != nil {
				return "", err
			}
			parts = append(parts, p)
		case d.name != "data-raw" && strings.HasPrefix(d.value, "@"):
			flag := "--" + d.name
			if d.short != "" {
				flag = "-" + d.short
			}
			return "", &refusalError{err: fmt.Errorf("%s @file is not supported: kuzl reads no local files", flag)}
		default:
			parts = append(parts, escapeQuery(d.value))
		}
	}
	return strings.Join(parts, "&"), nil
}

// urlencodeData encodes a --data-urlencode value as curl does. Up to the
// first =, it is a name, sent as given, and the rest is encoded; without an
// =, an @ would name a file to read (@file or name@file), and the value is
// otherwise encoded whole.
func urlencodeData(v string) (string, error) {
	if name, content, ok := strings.Cut(v, "="); ok {
		if name == "" {
			return escapeAll(content), nil
		}
		return escapeQuery(name) + "=" + escapeAll(content), nil
	}
	if strings.Contains(v, "@") {
		return "", &refusalError{err: fmt.Errorf("--data-urlencode %q is not supported: kuzl reads no local files; write name=content to send an @", v)}
	}
	return escapeAll(v), nil
}

// escapeAll percent-encodes every byte of s but the unreserved ones (RFC
// 3986), as curl_easy_escape does: a space is %20, not +.
func escapeAll(s string) string {
	return escapeExcept(s, "-._~")
}

// escapeQuery percent-encodes the bytes of s that can't be in a query (RFC
// 3986), such as spaces, control characters, # and non-ASCII. The rest, %
// included, is sent as given: -d's value is expected to be encoded already.
func escapeQuery(s string) string {
	return escapeExcept(s, "-._~!$&'()*+,;=:@/?%")
}

// escapeExcept percent-encodes the bytes of s other than letters, digits and
// the bytes in keep.
func escapeExcept(s, keep string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(keep, c) >= 0 {
			b.WriteByte(c)
		} else {
			b.Write([]byte{'%', hex[c>>4], hex[c&15]})
		}
	}
	return b.String()
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

// parseSize parses a --max-filesize value as curl does: a number of bytes,
// with k, M or G for 1024, 1024² or 1024³ of them.
func parseSize(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'k', 'K':
		mult = 1 << 10
	case 'm', 'M':
		mult = 1 << 20
	case 'g', 'G':
		mult = 1 << 30
	}
	if mult > 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > math.MaxInt64/mult {
		return 0, false
	}
	return n * mult, true
}

// expandWriteOut expands an -w format as curl does: %{name} is a variable from
// vars, %% is %, and \n, \r and \t are escapes. Any other backslash is
// written as is, \\ included. A variable kuzl doesn't know is an error, so
// newRequest checks the format with nil vars.
func expandWriteOut(format string, vars map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		c := format[i]
		switch {
		case strings.HasPrefix(format[i:], "%%"):
			b.WriteByte('%')
			i++
		case strings.HasPrefix(format[i:], "%{"):
			end := strings.IndexByte(format[i:], '}')
			if end < 0 {
				return "", errors.New(`"%{" without a closing "}"`)
			}
			name := format[i+2 : i+end]
			if !slices.Contains(writeOutNames, name) {
				return "", fmt.Errorf("unknown variable %%{%s}: kuzl knows %%{%s}", name, strings.Join(writeOutNames, "}, %{"))
			}
			b.WriteString(vars[name])
			i += end
		case c == '\\' && i+1 < len(format) && strings.IndexByte("nrt", format[i+1]) >= 0:
			b.WriteByte(map[byte]byte{'n': '\n', 'r': '\r', 't': '\t'}[format[i+1]])
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// writeOutVars are the -w variables for a transfer: resp is nil if there was
// no response, and size is how many bytes of body came.
func writeOutVars(req *http.Request, resp *http.Response, size int64) map[string]string {
	vars := map[string]string{
		"http_code":     "000",
		"content_type":  "",
		"url_effective": req.URL.String(),
		"size_download": strconv.FormatInt(size, 10),
	}
	if resp != nil {
		vars["http_code"] = fmt.Sprintf("%03d", resp.StatusCode)
		vars["content_type"] = resp.Header.Get("Content-Type")
		vars["url_effective"] = resp.Request.URL.String()
	}
	return vars
}

func (f *curlFlags) quiet() bool { return f.silent && !f.showError }

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// fetch sends req and writes the response: the headers of every hop with -i
// or -I, then the body, to the file in root with -o or -O, or else to stdout,
// capped at maxShowBytes. -w comes after, on stdout.
func (f *curlFlags) fetch(ctx context.Context, s IO, req *http.Request, root *workspace.Root, rec *record) error {
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
		err = f.transferError(err, time.Since(start))
		if _, ok := errors.AsType[*refusalError](err); ok {
			return err
		}
		// A hop may have answered before the failure, as past --max-redirs;
		// -w reports the last response, as curl does.
		var last *http.Response
		if n := len(hops.hops); n > 0 {
			last = hops.hops[n-1]
		}
		return f.writeOutAfter(s, req, last, 0, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rec.add("status", resp.StatusCode)
	size, err := f.writeResponse(s, req, resp, hops.hops, root, start, rec)
	return f.writeOutAfter(s, req, resp, size, err)
}

// writeResponse writes resp, with the headers of hops before it with -i or
// -I, to the file in root, or to stdout if root is nil. It returns how many
// bytes of body came.
func (f *curlFlags) writeResponse(s IO, req *http.Request, resp *http.Response, hops []*http.Response, root *workspace.Root, start time.Time, rec *record) (int64, error) {
	failed := resp.StatusCode >= 400 && (f.fail || f.failWithBody)
	httpErr := &curlError{
		code:  exitHTTPReturned,
		err:   fmt.Errorf("The requested URL returned error: %d", resp.StatusCode), //nolint:staticcheck // ST1005: curl's message.
		quiet: f.quiet(),
	}
	if failed && f.fail {
		return 0, httpErr
	}
	// As curl does, a body that says it is too big isn't read at all.
	limit := f.maxBytes
	if limit == 0 && root != nil {
		limit = maxDownloadBytes
	}
	if limit > 0 && resp.ContentLength > limit && req.Method != http.MethodHead {
		return 0, f.fileSizeError()
	}

	var head []byte
	if f.head || f.include {
		var b bytes.Buffer
		for _, h := range hops {
			writeHeaders(&b, h)
		}
		head = b.Bytes()
	}
	if root != nil {
		n, err := f.save(root, req, resp, head, limit, start, rec)
		if err == nil && failed {
			err = httpErr
		}
		return n, err
	}

	var body []byte
	var bodyErr error
	var size int64
	more, moreExact := int64(0), true
	if req.Method != http.MethodHead {
		show := max(maxShowBytes+1-len(head), 0)
		body, bodyErr = io.ReadAll(io.LimitReader(resp.Body, int64(show)))
		if bodyErr == nil && len(body) == show && (f.maxBytes == 0 || int64(show) <= f.maxBytes) {
			rest := int64(maxCountBytes)
			if f.maxBytes > 0 {
				rest = f.maxBytes - int64(show)
			}
			more, moreExact, bodyErr = countRest(resp, int64(show), rest)
		}
		size = int64(len(body)) + more
		rec.add("bytes", size)
		// Nothing is written of a body over --max-filesize.
		if f.maxBytes > 0 && (size > f.maxBytes || !moreExact) {
			return size, f.fileSizeError()
		}
	}

	data := append(head, body...)
	n := capAt(data, maxShowBytes)
	if shown := data[min(len(head), n):n]; bytes.IndexByte(shown, 0) >= 0 || !utf8.Valid(shown) {
		if _, err := s.Out.Write(data[:min(len(head), n)]); err != nil {
			return size, f.writeError(err)
		}
		// The failed request matters more to the caller than the binary body.
		if failed {
			return size, httpErr
		}
		what := "binary output"
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			what += " (Content-Type " + ct + ")"
		}
		return size, &curlError{code: exitWriteError, err: fmt.Errorf("%s is not written to stdout; use -o to save it", what)}
	}
	if _, err := s.Out.Write(data[:n]); err != nil {
		return size, f.writeError(err)
	}
	if left := int64(len(data)-n) + more; left > 0 {
		if moreExact {
			_, _ = fmt.Fprintf(s.ErrOut, "… truncated, %d more bytes; use -o to save it all\n", left)
		} else {
			_, _ = fmt.Fprintf(s.ErrOut, "… truncated, more than %d more bytes; use -o to save it all\n", left)
		}
	}
	if bodyErr != nil {
		return size, f.transferError(bodyErr, time.Since(start))
	}
	if failed {
		return size, httpErr
	}
	return size, nil
}

// save writes head and resp's body to the -o file in root, at most limit
// bytes of body. A body over limit fails with exit 63, leaving the part
// written, as curl does.
func (f *curlFlags) save(root *workspace.Root, req *http.Request, resp *http.Response, head []byte, limit int64, start time.Time, rec *record) (int64, error) {
	file, err := root.Create(f.outFile)
	if err != nil {
		return 0, &curlError{code: exitWriteError, err: fmt.Errorf("Failed to open the file %w", err), quiet: f.quiet()} //nolint:staticcheck // ST1005: curl's message.
	}
	w := &errWriter{w: file}
	_, _ = w.Write(head)
	var n int64
	var bodyErr error
	tooBig := false
	if req.Method != http.MethodHead {
		n, bodyErr = io.Copy(w, io.LimitReader(resp.Body, limit))
		if bodyErr == nil && n == limit {
			var one [1]byte
			k, _ := io.ReadFull(resp.Body, one[:])
			tooBig = k > 0
		}
		rec.add("bytes", n)
	}
	closeErr := file.Close()
	switch {
	case w.err != nil:
		return n, f.writeError(w.err)
	case tooBig:
		return n, f.fileSizeError()
	case bodyErr != nil:
		return n, f.transferError(bodyErr, time.Since(start))
	case closeErr != nil:
		return n, f.writeError(closeErr)
	}
	return n, nil
}

// errWriter keeps the first error its writer returns, so that a failed write
// to the file can be told from a failed read of the body in io.Copy.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

// writeOutAfter writes -w, if set, to stdout once the transfer is over,
// failed or not, as curl does, and returns err, the transfer's.
func (f *curlFlags) writeOutAfter(s IO, req *http.Request, resp *http.Response, size int64, err error) error {
	if f.writeOut == "" {
		return err
	}
	// newRequest has checked the format.
	out, _ := expandWriteOut(f.writeOut, writeOutVars(req, resp, size))
	if _, werr := io.WriteString(s.Out, out); werr != nil && err == nil {
		return f.writeError(werr)
	}
	return err
}

func (f *curlFlags) fileSizeError() error {
	return &curlError{code: exitFileSizeExceeded, err: errors.New("Maximum file size exceeded"), quiet: f.quiet()} //nolint:staticcheck // ST1005: curl's message.
}

// countRest returns how many bytes of resp's body are left after the first
// read ones. Its Content-Length says so without reading them, unless Go's
// client decompressed the body; otherwise the rest is read, up to limit
// bytes, and exact is false if there was more.
func countRest(resp *http.Response, read, limit int64) (n int64, exact bool, err error) {
	if resp.ContentLength >= read && !resp.Uncompressed {
		return resp.ContentLength - read, true, nil
	}
	n, err = io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
	return min(n, limit), n <= limit, err
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

// writeError is curl's exit 23 for output that can't be written, such as
// stdout on a closed pipe or a full disk under -o.
func (f *curlFlags) writeError(err error) error {
	return &curlError{
		code:  exitWriteError,
		err:   fmt.Errorf("Failure writing output to destination: %w", err), //nolint:staticcheck // ST1005: curl's message.
		quiet: f.quiet(),
	}
}

// transferError maps a failed request to curl's exit code and message. A
// request the policy refuses is a refusalError instead, which -s doesn't
// silence.
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
