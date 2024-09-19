// main.go

package main

import (
    "context"
    "flag"
    "fmt"
    "io"
    "math/rand"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "runtime"
    "runtime/debug"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/chromedp/cdproto/emulation"
    "github.com/chromedp/cdproto/network"
    "github.com/chromedp/cdproto/page"
    "github.com/chromedp/chromedp"
    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
    log "github.com/sirupsen/logrus"
)

const (
    defaultGracefulTimeout = 5 * time.Second
)

var (
    debugOutput      = false
    ignoreCertErrors = true
    proxyServer      = ""
    disableSandbox   = false
)

type application struct{}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randStringRunes(n int) string {
    b := make([]rune, n)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(b)
}

func main() {
    var host string
    var wait time.Duration
    flag.StringVar(&host, "host", "127.0.0.1:8080", "IP and Port to bind to")
    flag.BoolVar(&ignoreCertErrors, "ignore-cert-errors", true, "Ignore Certificate Errors when taking screenshots or fetching resources")
    flag.BoolVar(&debugOutput, "debug", false, "Enable DEBUG mode")
    flag.BoolVar(&disableSandbox, "disable-sandbox", false, "Disable chromium sandbox")
    flag.StringVar(&proxyServer, "proxy", "", "Proxy Server to use for chromium. Please use format IP:PORT without a protocol.")
    flag.DurationVar(&wait, "graceful-timeout", defaultGracefulTimeout, "the duration for which the server gracefully waits for existing connections to finish - e.g. 15s or 1m")
    flag.Parse()

    log.SetOutput(os.Stdout)
    log.SetLevel(log.InfoLevel)
    if debugOutput {
        log.SetLevel(log.DebugLevel)
    }

    app := &application{}

    srv := &http.Server{
        Addr:    host,
        Handler: app.routes(),
    }
    log.Infof("Starting server on %s", host)
    if debugOutput {
        log.Debug("DEBUG mode enabled")
    }

    // Print number of goroutines in debug mode
    if debugOutput {
        go func() {
            goRoutineTicker := time.NewTicker(3 * time.Second)
            for range goRoutineTicker.C {
                log.Debugf("number of goroutines: %d", runtime.NumGoroutine())
            }
        }()
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil {
            log.Error(err)
        }
    }()

    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
    <-c
    ctx, cancel := context.WithTimeout(context.Background(), wait)
    defer cancel()
    if err := srv.Shutdown(ctx); err != nil {
        log.Error(err)
    }
    log.Info("shutting down")
    os.Exit(0)
}

func (app *application) routes() http.Handler {
    r := mux.NewRouter()
    r.Use(app.loggingMiddleware)
    r.Use(app.recoverPanic)
    r.HandleFunc("/screenshot", app.errorHandler(app.screenshot))
    r.HandleFunc("/html2pdf", app.errorHandler(app.html2pdf))
    r.HandleFunc("/url2pdf", app.errorHandler(app.url2pdf))
    r.HandleFunc("/html", app.errorHandler(app.html))
    r.PathPrefix("/").HandlerFunc(app.catchAllHandler)
    return r
}

func (app *application) catchAllHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Connection", "close")
    w.WriteHeader(http.StatusNotFound)
    if _, err := w.Write([]byte("Not found")); err != nil {
        log.Error(err)
    }
}

func (app *application) loggingMiddleware(next http.Handler) http.Handler {
    return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func (app *application) toImage(ctx context.Context, url string, w, h *int, userAgent *string, headers map[string]string) ([]byte, error) {
    return app.chromedpAction(ctx, url, w, h, userAgent, headers, "screenshot", nil, nil, nil, nil, nil, nil, nil)
}

func (app *application) toPDF(
    ctx context.Context,
    url string,
    w, h *int,
    userAgent *string,
    headers map[string]string,
    preferCSSPageSize, landscape *bool,
    marginTop, marginBottom, marginLeft, marginRight *float64,
    pageSize *string,
) ([]byte, error) {
    return app.chromedpAction(
        ctx, url, w, h, userAgent, headers, "pdf",
        preferCSSPageSize, landscape,
        marginTop, marginBottom, marginLeft, marginRight,
        pageSize,
    )
}

func (app *application) toHTML(ctx context.Context, url string, w, h *int, userAgent *string, headers map[string]string) ([]byte, error) {
    return app.chromedpAction(ctx, url, w, h, userAgent, headers, "html", nil, nil, nil, nil, nil, nil, nil)
}

func (app *application) chromedpAction(
    ctx context.Context,
    url string,
    w, h *int,
    userAgent *string,
    headers map[string]string,
    action string,
    preferCSSPageSize, landscape *bool,
    marginTop, marginBottom, marginLeft, marginRight *float64,
    pageSizeParam *string,
) ([]byte, error) {
    opts := append(chromedp.DefaultExecAllocatorOptions[:],
        chromedp.Flag("headless", true),
        chromedp.Flag("disable-gpu", true),
        chromedp.Flag("hide-scrollbars", true),
        chromedp.Flag("mute-audio", true),
        chromedp.Flag("disable-software-rasterizer", true),
        chromedp.Flag("disable-dev-shm-usage", true),
        chromedp.Flag("disable-crash-reporter", true),
        chromedp.Flag("block-new-web-contents", true),
    )

    if ignoreCertErrors {
        opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
    }

    if disableSandbox {
        opts = append(opts, chromedp.Flag("no-sandbox", true))
    }

    if proxyServer != "" {
        opts = append(opts, chromedp.ProxyServer(proxyServer))
    }

    allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
    defer cancel()

    ctx, cancel = chromedp.NewContext(allocCtx)
    defer cancel()

    // Set up timeout
    ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
    defer cancel()

    // Enable network and set headers
    var tasks chromedp.Tasks
    tasks = append(tasks, network.Enable())

    if userAgent != nil && *userAgent != "" {
        tasks = append(tasks, emulation.SetUserAgentOverride(*userAgent))
    }

    if len(headers) > 0 {
        headersInterface := network.Headers{}
        for k, v := range headers {
            headersInterface[k] = v
        }
        tasks = append(tasks, network.SetExtraHTTPHeaders(headersInterface))
    }

    // Set viewport size if provided
    if w != nil && h != nil {
        tasks = append(tasks, emulation.SetDeviceMetricsOverride(int64(*w), int64(*h), 1.0, false))
    }

    var buf []byte
    var htmlContent string

    // Variables for tracking network activity
    var (
        activeRequests int
        networkMu      sync.Mutex
        networkIdleAt  time.Time
    )

    // Listen to network events to detect when network is idle
    chromedp.ListenTarget(ctx, func(event interface{}) {
        switch event.(type) {
        case *network.EventRequestWillBeSent:
            networkMu.Lock()
            activeRequests++
            networkIdleAt = time.Time{} // Reset idle timer
            networkMu.Unlock()
        case *network.EventLoadingFinished, *network.EventLoadingFailed:
            networkMu.Lock()
            if activeRequests > 0 {
                activeRequests--
            }
            if activeRequests <= 2 {
                if networkIdleAt.IsZero() {
                    networkIdleAt = time.Now()
                }
            } else {
                networkIdleAt = time.Time{} // Reset idle timer
            }
            networkMu.Unlock()
        }
    })

    // Navigate and wait for network idle
    tasks = append(tasks,
        chromedp.Navigate(url),
        chromedp.WaitReady("body", chromedp.ByQuery),
        chromedp.ActionFunc(func(ctx context.Context) error {
            // Wait until activeRequests <= 2 for at least 500ms
            ticker := time.NewTicker(100 * time.Millisecond)
            defer ticker.Stop()

            timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
            defer cancel()

            for {
                select {
                case <-ticker.C:
                    networkMu.Lock()
                    idleDuration := time.Since(networkIdleAt)
                    if activeRequests <= 2 && !networkIdleAt.IsZero() && idleDuration >= 10*time.Second {
                        networkMu.Unlock()
                        return nil
                    }
                    networkMu.Unlock()
                case <-timeoutCtx.Done():
                    return fmt.Errorf("timeout waiting for network to be idle")
                case <-ctx.Done():
                    return ctx.Err()
                }
            }
        }),
    )

    switch action {
    case "screenshot":
        tasks = append(tasks,
            chromedp.FullScreenshot(&buf, 90),
        )
    case "pdf":
        tasks = append(tasks,
            chromedp.ActionFunc(func(ctx context.Context) error {
                var err error
                preferCSS := false
                if preferCSSPageSize != nil {
                    preferCSS = *preferCSSPageSize
                }
                isLandscape := false
                if landscape != nil {
                    isLandscape = *landscape
                }

                // Set margins, default to 0 if not provided
                marginTopValue := 0.0
                if marginTop != nil {
                    marginTopValue = *marginTop
                }
                marginBottomValue := 0.0
                if marginBottom != nil {
                    marginBottomValue = *marginBottom
                }
                marginLeftValue := 0.0
                if marginLeft != nil {
                    marginLeftValue = *marginLeft
                }
                marginRightValue := 0.0
                if marginRight != nil {
                    marginRightValue = *marginRight
                }

                // Set paper size, default to A4 size
                paperWidthValue := 8.27  // A4 width in inches
                paperHeightValue := 11.69 // A4 height in inches

                if pageSizeParam != nil {
                    pageSize := strings.ToUpper(*pageSizeParam)
                    if dimensions, ok := pageSizes[pageSize]; ok {
                        paperWidthValue = dimensions.width
                        paperHeightValue = dimensions.height
                    } else {
                        return fmt.Errorf("invalid pageSize parameter: %s", *pageSizeParam)
                    }
                } else if preferCSS {
                    // When preferCSSPageSize is true, paper size is determined by CSS
                    paperWidthValue = 0
                    paperHeightValue = 0
                }

                // Orientation is handled by WithLandscape(isLandscape)
                // No need to swap width and height

                // Ensure content area is positive
                if (marginLeftValue+marginRightValue) >= paperWidthValue && paperWidthValue > 0 {
                    return fmt.Errorf("margins are too large for the page width")
                }
                if (marginTopValue+marginBottomValue) >= paperHeightValue && paperHeightValue > 0 {
                    return fmt.Errorf("margins are too large for the page height")
                }

                buf, _, err = page.PrintToPDF().
                    WithPreferCSSPageSize(preferCSS).
                    WithLandscape(isLandscape).
                    WithMarginTop(marginTopValue).
                    WithMarginBottom(marginBottomValue).
                    WithMarginLeft(marginLeftValue).
                    WithMarginRight(marginRightValue).
                    WithPaperWidth(paperWidthValue).
                    WithPaperHeight(paperHeightValue).
                    Do(ctx)
                return err
            }),
        )
    case "html":
        tasks = append(tasks,
            chromedp.OuterHTML("html", &htmlContent),
        )
    default:
        return nil, fmt.Errorf("unknown action %q", action)
    }

    // Run tasks
    if err := chromedp.Run(ctx, tasks); err != nil {
        return nil, err
    }

    if action == "html" {
        return []byte(htmlContent), nil
    }

    return buf, nil
}

func (app *application) logError(w http.ResponseWriter, err error, withTrace bool) {
    w.Header().Set("Connection", "close")
    errorText := fmt.Sprintf("%v", err)
    log.Error(errorText)
    if withTrace {
        log.Errorf("%s", debug.Stack())
    }
    http.Error(w, "There was an error processing your request", http.StatusInternalServerError)
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                app.logError(w, fmt.Errorf("%s", err), true)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

func (app *application) errorHandler(h func(*http.Request) (string, []byte, error)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        content, b, err := h(r)
        if err != nil {
            app.logError(w, err, false)
            return
        }
        w.Header().Set("Content-Type", content)
        _, err = w.Write(b)
        if err != nil {
            app.logError(w, err, false)
            return
        }
    }
}

func getStringParameter(r *http.Request, paramname string) *string {
    p, ok := r.URL.Query()[paramname]
    if !ok || len(p[0]) < 1 {
        return nil
    }
    ret := p[0]
    return &ret
}

func getIntParameter(r *http.Request, paramname string) (*int, error) {
    p, ok := r.URL.Query()[paramname]
    if !ok || len(p[0]) < 1 {
        return nil, nil
    }

    i, err := strconv.Atoi(p[0])
    if err != nil {
        return nil, fmt.Errorf("invalid parameter %s=%q - %w", paramname, p[0], err)
    } else if i < 0 {
        return nil, fmt.Errorf("invalid parameter %s: %q", paramname, p[0])
    }

    return &i, nil
}

// Helper function to parse boolean parameters
func getBoolParameter(r *http.Request, paramname string) (*bool, error) {
    p, ok := r.URL.Query()[paramname]
    if !ok || len(p[0]) < 1 {
        return nil, nil
    }

    b, err := strconv.ParseBool(p[0])
    if err != nil {
        return nil, fmt.Errorf("invalid parameter %s=%q - %w", paramname, p[0], err)
    }

    return &b, nil
}

// Helper function to parse float parameters
func getFloatParameter(r *http.Request, paramname string) (*float64, error) {
    p, ok := r.URL.Query()[paramname]
    if !ok || len(p[0]) < 1 {
        return nil, nil
    }

    f, err := strconv.ParseFloat(p[0], 64)
    if err != nil {
        return nil, fmt.Errorf("invalid parameter %s=%q - %w", paramname, p[0], err)
    }

    return &f, nil
}

// Helper function to parse headers parameter
func parseHeaders(headersParam *string) map[string]string {
    headers := make(map[string]string)
    if headersParam != nil && *headersParam != "" {
        headersList := strings.Split(*headersParam, ",")
        for _, header := range headersList {
            parts := strings.SplitN(header, "___", 2)
            if len(parts) == 2 {
                headerName := strings.TrimSpace(parts[0])
                headerValue := strings.TrimSpace(parts[1])
                headers[headerName] = headerValue
            }
        }
    }
    return headers
}

// Helper function to convert pixels to inches
func pixelsToInches(pixels int) float64 {
    return float64(pixels) / 96.0
}

// Map of standard page sizes to their dimensions in inches
var pageSizes = map[string]struct {
    width  float64
    height float64
}{
    "A0":     {width: 33.11, height: 46.81},
    "A1":     {width: 23.39, height: 33.11},
    "A2":     {width: 16.54, height: 23.39},
    "A3":     {width: 11.69, height: 16.54},
    "A4":     {width: 8.27, height: 11.69},
    "A5":     {width: 5.83, height: 8.27},
    "A6":     {width: 4.13, height: 5.83},
    "A7":     {width: 2.91, height: 4.13},
    "A8":     {width: 2.05, height: 2.91},
    "A9":     {width: 1.46, height: 2.05},
    "A10":    {width: 1.02, height: 1.46},
    "Letter": {width: 8.5, height: 11.0},
    "Legal":  {width: 8.5, height: 14.0},
}

// http://localhost:8080/screenshot?url=https://example.com&w=1024&h=768&headers=Authorization___Bearer%20token123,X-Custom-Header___CustomValue
func (app *application) screenshot(r *http.Request) (string, []byte, error) {
    url := getStringParameter(r, "url")
    if url == nil {
        return "", nil, fmt.Errorf("missing required parameter url")
    }

    // Optional parameters start here
    w, err := getIntParameter(r, "w")
    if err != nil {
        return "", nil, err
    }

    h, err := getIntParameter(r, "h")
    if err != nil {
        return "", nil, err
    }

    userAgentParam := getStringParameter(r, "useragent")
    headersParam := getStringParameter(r, "headers")
    headers := parseHeaders(headersParam)

    content, err := app.toImage(r.Context(), *url, w, h, userAgentParam, headers)
    if err != nil {
        return "", nil, err
    }

    return "image/png", content, nil
}

// http://localhost:8080/html2pdf?w=1024&h=768&preferCSSPageSize=true&landscape=true&marginTop=96&marginBottom=96&marginLeft=48&marginRight=48&pageSize=A4
func (app *application) html2pdf(r *http.Request) (string, []byte, error) {
    // Optional parameters start here
    w, err := getIntParameter(r, "w")
    if err != nil {
        return "", nil, err
    }

    h, err := getIntParameter(r, "h")
    if err != nil {
        return "", nil, err
    }

    userAgentParam := getStringParameter(r, "useragent")
    headersParam := getStringParameter(r, "headers")
    headers := parseHeaders(headersParam)

    preferCSSPageSizeParam, err := getBoolParameter(r, "preferCSSPageSize")
    if err != nil {
        return "", nil, err
    }

    landscapeParam, err := getBoolParameter(r, "landscape")
    if err != nil {
        return "", nil, err
    }

    // Parse margins in pixels and convert to inches
    marginTopPx, err := getIntParameter(r, "marginTop")
    if err != nil {
        return "", nil, err
    }
    var marginTopParam *float64
    if marginTopPx != nil {
        marginTopInches := pixelsToInches(*marginTopPx)
        marginTopParam = &marginTopInches
    }

    marginBottomPx, err := getIntParameter(r, "marginBottom")
    if err != nil {
        return "", nil, err
    }
    var marginBottomParam *float64
    if marginBottomPx != nil {
        marginBottomInches := pixelsToInches(*marginBottomPx)
        marginBottomParam = &marginBottomInches
    }

    marginLeftPx, err := getIntParameter(r, "marginLeft")
    if err != nil {
        return "", nil, err
    }
    var marginLeftParam *float64
    if marginLeftPx != nil {
        marginLeftInches := pixelsToInches(*marginLeftPx)
        marginLeftParam = &marginLeftInches
    }

    marginRightPx, err := getIntParameter(r, "marginRight")
    if err != nil {
        return "", nil, err
    }
    var marginRightParam *float64
    if marginRightPx != nil {
        marginRightInches := pixelsToInches(*marginRightPx)
        marginRightParam = &marginRightInches
    }

    // Parse page size
    pageSizeParam := getStringParameter(r, "pageSize")

    // Read HTML content from POST body
    bodyBytes, err := io.ReadAll(r.Body)
    if err != nil {
        return "", nil, fmt.Errorf("could not read request body: %w", err)
    }
    if len(bodyBytes) == 0 {
        return "", nil, fmt.Errorf("please provide a valid post body")
    }

    // Create a temporary HTML file
    tmpf, err := os.CreateTemp("", "html2pdf.*.html")
    if err != nil {
        return "", nil, fmt.Errorf("could not create temp file: %w", err)
    }
    defer os.Remove(tmpf.Name())

    if _, err := tmpf.Write(bodyBytes); err != nil {
        return "", nil, fmt.Errorf("could not write to temp file: %w", err)
    }
    if err := tmpf.Close(); err != nil {
        return "", nil, fmt.Errorf("could not close temp file: %w", err)
    }

    path, err := filepath.Abs(tmpf.Name())
    if err != nil {
        return "", nil, fmt.Errorf("could not get temp file path: %w", err)
    }

    content, err := app.toPDF(r.Context(), "file://"+path, w, h, userAgentParam, headers,
        preferCSSPageSizeParam, landscapeParam,
        marginTopParam, marginBottomParam, marginLeftParam, marginRightParam,
        pageSizeParam)
    if err != nil {
        return "", nil, err
    }

    return "application/pdf", content, nil
}

// http://localhost:8080/url2pdf?url=https://example.com&w=1024&h=768&preferCSSPageSize=true&landscape=true&marginTop=96&marginBottom=96&marginLeft=48&marginRight=48&pageSize=A4&headers=Authorization___Bearer%20token123,X-Custom-Header___CustomValue
func (app *application) url2pdf(r *http.Request) (string, []byte, error) {
    url := getStringParameter(r, "url")
    if url == nil {
        return "", nil, fmt.Errorf("missing required parameter url")
    }

    // Optional parameters start here
    w, err := getIntParameter(r, "w")
    if err != nil {
        return "", nil, err
    }

    h, err := getIntParameter(r, "h")
    if err != nil {
        return "", nil, err
    }

    userAgentParam := getStringParameter(r, "useragent")
    headersParam := getStringParameter(r, "headers")
    headers := parseHeaders(headersParam)

    preferCSSPageSizeParam, err := getBoolParameter(r, "preferCSSPageSize")
    if err != nil {
        return "", nil, err
    }

    landscapeParam, err := getBoolParameter(r, "landscape")
    if err != nil {
        return "", nil, err
    }

    // Parse margins in pixels and convert to inches
    marginTopPx, err := getIntParameter(r, "marginTop")
    if err != nil {
        return "", nil, err
    }
    var marginTopParam *float64
    if marginTopPx != nil {
        marginTopInches := pixelsToInches(*marginTopPx)
        marginTopParam = &marginTopInches
    }

    marginBottomPx, err := getIntParameter(r, "marginBottom")
    if err != nil {
        return "", nil, err
    }
    var marginBottomParam *float64
    if marginBottomPx != nil {
        marginBottomInches := pixelsToInches(*marginBottomPx)
        marginBottomParam = &marginBottomInches
    }

    marginLeftPx, err := getIntParameter(r, "marginLeft")
    if err != nil {
        return "", nil, err
    }
    var marginLeftParam *float64
    if marginLeftPx != nil {
        marginLeftInches := pixelsToInches(*marginLeftPx)
        marginLeftParam = &marginLeftInches
    }

    marginRightPx, err := getIntParameter(r, "marginRight")
    if err != nil {
        return "", nil, err
    }
    var marginRightParam *float64
    if marginRightPx != nil {
        marginRightInches := pixelsToInches(*marginRightPx)
        marginRightParam = &marginRightInches
    }

    // Parse page size
    pageSizeParam := getStringParameter(r, "pageSize")

    content, err := app.toPDF(r.Context(), *url, w, h, userAgentParam, headers,
        preferCSSPageSizeParam, landscapeParam,
        marginTopParam, marginBottomParam, marginLeftParam, marginRightParam,
        pageSizeParam)
    if err != nil {
        return "", nil, err
    }

    return "application/pdf", content, nil
}

// http://localhost:8080/html?url=https://example.com&w=1024&h=768&headers=Authorization___Bearer%20token123,X-Custom-Header___CustomValue
func (app *application) html(r *http.Request) (string, []byte, error) {
    url := getStringParameter(r, "url")
    if url == nil {
        return "", nil, fmt.Errorf("missing required parameter url")
    }

    // Optional parameters start here
    w, err := getIntParameter(r, "w")
    if err != nil {
        return "", nil, err
    }

    h, err := getIntParameter(r, "h")
    if err != nil {
        return "", nil, err
    }

    userAgentParam := getStringParameter(r, "useragent")
    headersParam := getStringParameter(r, "headers")
    headers := parseHeaders(headersParam)

    content, err := app.toHTML(r.Context(), *url, w, h, userAgentParam, headers)
    if err != nil {
        return "", nil, err
    }

    return "text/html", content, nil
}

