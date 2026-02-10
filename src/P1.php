<?php
/**
 * P1 Framework — PHP 8.4+ micro-framework
 * Single-file, zero dependencies
 *
 * Usage: require 'P1.php'; class P1 extends \P1\Base {}
 */
declare(strict_types=1);

namespace P1 {

    class HttpException extends \RuntimeException {
        public function __construct(
            public readonly int $statusCode,
            string $message = '',
            ?\Throwable $previous = null,
            public readonly array $headers = [],
        ) {
            parent::__construct($message, $statusCode, $previous);
        }

        public static function notFound(string $msg = 'Not Found'): static {
            return new static(404, $msg);
        }

        public static function forbidden(string $msg = 'Forbidden'): static {
            return new static(403, $msg);
        }

        public static function unauthorized(string $msg = 'Unauthorized'): static {
            return new static(401, $msg);
        }

        public static function methodNotAllowed(array $allowed, string $msg = 'Method Not Allowed'): static {
            $methods = [];
            foreach ($allowed as $method) {
                $m = strtoupper((string) $method);
                if (!isset($methods[$m])) {
                    $methods[$m] = true;
                }
            }
            $allow = implode(', ', array_keys($methods));
            return new static(405, $msg, null, ['Allow' => $allow]);
        }
    }

    class Request {
        private array $params = [];

        public function __construct(
            public readonly string $method,
            public readonly string $path,
            public readonly array $query = [],
            public readonly array $post = [],
            public readonly array $server = [],
            public readonly array $headers = [],
            public readonly array $cookies = [],
            public readonly array $files = [],
            public readonly string $ip = '',
            public readonly string $body = '',
        ) {
        }

        public static function fromGlobals(): static {
            return self::buildFromGlobals((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        }

        public static function fromGlobalsWithProxies(array $trustedProxies = []): static {
            $headers = self::parseServerHeaders($_SERVER);
            return self::buildFromGlobals(self::resolveIp($_SERVER, $headers, $trustedProxies));
        }

        private static function buildFromGlobals(string $ip): static {
            $uri = $_SERVER['REQUEST_URI'] ?? '/';
            $path = parse_url($uri, PHP_URL_PATH) ?: '/';
            $headers = self::parseServerHeaders($_SERVER);

            return new static(
                method: strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
                path: (string) $path,
                query: $_GET,
                post: $_POST,
                server: $_SERVER,
                headers: $headers,
                cookies: $_COOKIE,
                files: $_FILES,
                ip: $ip,
                body: (string) (file_get_contents('php://input') ?: ''),
            );
        }

        private static function parseServerHeaders(array $server): array {
            $headers = [];
            foreach ($server as $key => $value) {
                if (!str_starts_with($key, 'HTTP_')) {
                    continue;
                }
                $name = str_replace('_', '-', substr($key, 5));
                $headers[ucwords(strtolower($name), '-')] = (string) $value;
            }
            if (isset($server['CONTENT_TYPE'])) {
                $headers['Content-Type'] = (string) $server['CONTENT_TYPE'];
            }
            if (isset($server['CONTENT_LENGTH'])) {
                $headers['Content-Length'] = (string) $server['CONTENT_LENGTH'];
            }
            return $headers;
        }

        private static function resolveIp(array $server, array $headers, array $trustedProxies): string {
            $remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
            if ($remoteAddr === '') {
                return '';
            }

            if ($trustedProxies === [] || !in_array($remoteAddr, $trustedProxies, true)) {
                return $remoteAddr;
            }

            $xff = (string) ($server['HTTP_X_FORWARDED_FOR'] ?? '');
            if ($xff !== '') {
                foreach (array_map('trim', explode(',', $xff)) as $ip) {
                    if ($ip === '' || in_array($ip, $trustedProxies, true)) {
                        continue;
                    }
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        return $ip;
                    }
                }
            }

            $realIp = (string) ($server['HTTP_X_REAL_IP'] ?? '');
            if ($realIp !== '' && filter_var($realIp, FILTER_VALIDATE_IP)) {
                return $realIp;
            }

            return $remoteAddr;
        }

        public function query(string $key, mixed $default = null): mixed {
            return $this->query[$key] ?? $default;
        }

        public function post(string $key, mixed $default = null): mixed {
            return $this->post[$key] ?? $default;
        }

        public function cookie(string $key, mixed $default = null): mixed {
            return $this->cookies[$key] ?? $default;
        }

        public function file(string $key, mixed $default = null): mixed {
            return $this->files[$key] ?? $default;
        }

        public function header(string $name, ?string $default = null): ?string {
            $needle = strtolower($name);
            foreach ($this->headers as $key => $value) {
                if (strtolower((string) $key) === $needle) {
                    return (string) $value;
                }
            }
            return $default;
        }

        public function param(string $key, mixed $default = null): mixed {
            return $this->params[$key] ?? $default;
        }

        public function setParams(array $params): void {
            $this->params = $params;
        }

        public function only(array $keys): array {
            $merged = array_merge($this->query, $this->post);
            $out = [];
            foreach ($keys as $key) {
                $out[$key] = $merged[$key] ?? null;
            }
            return $out;
        }

        public function isPost(): bool {
            return $this->method === 'POST';
        }

        public function isGet(): bool {
            return $this->method === 'GET';
        }

        public function isAjax(): bool {
            return strtolower($this->header('X-Requested-With') ?? '') === 'xmlhttprequest';
        }

        public function jsonBody(): ?array {
            if ($this->body === '') {
                return null;
            }
            $decoded = json_decode($this->body, true);
            return is_array($decoded) ? $decoded : null;
        }
    }

    class Response {
        public function __construct(
            public string $body = '',
            public int $status = 200,
            public array $headers = [],
        ) {
        }

        public static function html(string $body, int $status = 200): static {
            return new static($body, $status, ['Content-Type' => 'text/html; charset=UTF-8']);
        }

        public static function json(mixed $data, int $status = 200): static {
            return new static(
                json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
                $status,
                ['Content-Type' => 'application/json'],
            );
        }

        public static function redirect(string $url, int $status = 302): static {
            if (!str_starts_with($url, '/') && !str_starts_with($url, '//')) {
                $host = parse_url($url, PHP_URL_HOST);
                $currentHost = $_SERVER['HTTP_HOST'] ?? '';
                if ($host !== null && $currentHost !== '' && $host !== $currentHost) {
                    throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
                }
            }
            return new static('', $status, ['Location' => $url]);
        }

        public function send(): void {
            http_response_code($this->status);
            foreach ($this->headers as $name => $value) {
                header($name . ': ' . $value);
            }
            echo $this->body;
        }
    }

    class App {
        private static ?self $instance = null;
        private static bool $shutdownRegistered = false;

        private array $configData = [];

        /** @var array<int, array{methods: string[], pattern: string, regex: string, paramNames: string[], controller: string, action: string, middleware: array, name: ?string, ajax: bool}> */
        private array $routes = [];

        /** @var array<string, int> */
        private array $namedRoutes = [];

        /** @var array<callable> */
        private array $middleware = [];

        private ?Db $db = null;

        private float $startTime;

        public function __construct() {
            $this->startTime = microtime(true);
            self::$instance = $this;
            $this->registerErrorHandlers();
        }

        public function elapsed(): float {
            return microtime(true) - $this->startTime;
        }

        public static function instance(): static {
            if (self::$instance === null) {
                self::$instance = new static();
            }
            return self::$instance;
        }

        public function loadConfig(string $path): void {
            if (!is_file($path)) {
                throw new \RuntimeException('Config file not found: ' . $path);
            }
            $values = require $path;
            if (!is_array($values)) {
                throw new \RuntimeException('Config file must return array: ' . $path);
            }
            $this->configData = array_replace_recursive($this->configData, $values);
            if (isset($this->configData['timezone']) && is_string($this->configData['timezone'])) {
                date_default_timezone_set($this->configData['timezone']);
            }
        }

        public function config(string $key, mixed $default = null): mixed {
            if (array_key_exists($key, $this->configData)) {
                return $this->configData[$key];
            }

            $segments = explode('.', $key);
            $value = $this->configData;
            foreach ($segments as $segment) {
                if (!is_array($value) || !array_key_exists($segment, $value)) {
                    return $default;
                }
                $value = $value[$segment];
            }
            return $value;
        }

        public function setConfig(string $key, mixed $value): void {
            $segments = explode('.', $key);
            if (count($segments) === 1) {
                $this->configData[$key] = $value;
                return;
            }

            $cursor = &$this->configData;
            $lastIndex = count($segments) - 1;
            foreach ($segments as $i => $segment) {
                if ($i === $lastIndex) {
                    $cursor[$segment] = $value;
                    break;
                }
                if (!isset($cursor[$segment]) || !is_array($cursor[$segment])) {
                    $cursor[$segment] = [];
                }
                $cursor = &$cursor[$segment];
            }
        }

        public function db(): Db {
            if ($this->db === null) {
                $config = $this->config('db');
                if (!is_array($config)) {
                    throw new \RuntimeException('Database not configured.');
                }
                $this->db = new Db($config);
            }
            return $this->db;
        }

        public function setDb(Db $db): void {
            $this->db = $db;
        }

        public function get(string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void {
            $this->addRoute('GET|HEAD', $path, $controller, $action, $mw, $name, $ajax);
        }

        public function post(string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void {
            $this->addRoute('POST', $path, $controller, $action, $mw, $name, $ajax);
        }

        public function route(string $methods, string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void {
            $this->addRoute($methods, $path, $controller, $action, $mw, $name, $ajax);
        }

        private function addRoute(
            string $methods,
            string $pattern,
            string $controller,
            string $action,
            array $middleware,
            ?string $name,
            bool $ajax,
        ): void {
            $methodList = array_values(array_filter(array_map('trim', explode('|', strtoupper($methods)))));
            $paramNames = [];
            $parts = preg_split('/(\{\w+\}|\*)/', $pattern, -1, PREG_SPLIT_DELIM_CAPTURE);
            $regex = '';
            foreach ($parts as $part) {
                if (preg_match('/^\{(\w+)\}$/', $part, $matches)) {
                    $paramNames[] = $matches[1];
                    $regex .= '([^/]+)';
                    continue;
                }
                if ($part === '*') {
                    $paramNames[] = '*';
                    $regex .= '(.*)';
                    continue;
                }
                $regex .= preg_quote($part, '#');
            }

            $index = count($this->routes);
            $this->routes[] = [
                'methods' => $methodList,
                'pattern' => $pattern,
                'regex' => '#^' . $regex . '/?$#u',
                'paramNames' => $paramNames,
                'controller' => $controller,
                'action' => $action,
                'middleware' => $middleware,
                'name' => $name,
                'ajax' => $ajax,
            ];
            if ($name !== null) {
                $this->namedRoutes[$name] = $index;
            }
        }

        public function url(string $name, array $params = []): string {
            if (!isset($this->namedRoutes[$name])) {
                throw new \RuntimeException('Route not found: ' . $name);
            }
            $route = $this->routes[$this->namedRoutes[$name]];
            $url = $route['pattern'];
            foreach ($params as $key => $value) {
                $url = str_replace('{' . $key . '}', rawurlencode((string) $value), $url);
            }
            return $url;
        }

        public function addMiddleware(callable $middleware): void {
            $this->middleware[] = $middleware;
        }

        public function handle(Request $request): Response {
            $handler = fn (Request $req): Response => $this->dispatch($req);
            foreach (array_reverse($this->middleware) as $mw) {
                $next = $handler;
                $handler = fn (Request $req): Response => $mw($req, $next);
            }

            return $this->withErrorHandler(function () use ($handler, $request): Response {
                try {
                    return $handler($request);
                } catch (HttpException $e) {
                    return $this->handleHttpException($e);
                } catch (\Throwable $e) {
                    return $this->handleException($e);
                }
            });
        }

        private function dispatch(Request $request): Response {
            $match = $this->matchRoute($request->method, $request->path, $request->isAjax());
            if ($match === null) {
                throw HttpException::notFound();
            }

            $request->setParams($match['params']);

            $handler = fn (Request $req): Response => $this->invokeController(
                $req,
                $match['controller'],
                $match['action'],
            );

            foreach (array_reverse($match['middleware']) as $mw) {
                $next = $handler;
                $handler = fn (Request $req): Response => $mw($req, $next);
            }

            return $handler($request);
        }

        private function matchRoute(string $method, string $path, bool $isAjax): ?array {
            $method = strtoupper($method);
            $allowed = [];
            foreach ($this->routes as $route) {
                if (!preg_match($route['regex'], $path, $matches)) {
                    continue;
                }
                if ($route['ajax'] && !$isAjax) {
                    continue;
                }
                if (!in_array($method, $route['methods'], true)) {
                    foreach ($route['methods'] as $allowedMethod) {
                        $allowed[$allowedMethod] = true;
                    }
                    continue;
                }

                $params = [];
                foreach ($route['paramNames'] as $i => $name) {
                    $params[$name] = $matches[$i + 1] ?? '';
                }

                return [
                    'controller' => $route['controller'],
                    'action' => $route['action'],
                    'params' => $params,
                    'middleware' => $route['middleware'],
                ];
            }

            if ($allowed !== []) {
                throw HttpException::methodNotAllowed(array_keys($allowed));
            }

            return null;
        }

        private function invokeController(Request $request, string $controllerClass, string $action): Response {
            $controller = new $controllerClass();

            if (property_exists($controller, 'request')) {
                $controller->request = $request;
            }

            if (method_exists($controller, 'beforeRoute')) {
                $hook = $controller->beforeRoute();
                if ($hook instanceof Response) {
                    return $hook;
                }
            }

            if (!method_exists($controller, $action)) {
                throw new \RuntimeException('Action not found: ' . $controllerClass . '::' . $action);
            }

            $result = $controller->{$action}();

            if (method_exists($controller, 'afterRoute')) {
                $hook = $controller->afterRoute();
                if ($hook instanceof Response) {
                    return $hook;
                }
            }

            if ($result instanceof Response) {
                return $result;
            }

            return new Response((string) ($result ?? ''));
        }

        private function handleHttpException(HttpException $e): Response {
            $debug = (int) $this->config('debug', 0);
            $body = $debug >= 3 ? $e->getMessage() : match ($e->statusCode) {
                401 => 'Wymagane logowanie',
                403 => 'Brak dostępu',
                404 => 'Nie znaleziono',
                405 => 'Niedozwolona metoda',
                default => 'Błąd serwera',
            };
            return new Response($body, $e->statusCode, $e->headers);
        }

        private function handleException(\Throwable $e): Response {
            Log::error('Unhandled exception', [
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);
            $debug = (int) $this->config('debug', 0);
            $body = $debug >= 3
                ? $e->getMessage() . "\n" . $e->getTraceAsString()
                : 'Wystąpił błąd serwera.';
            return new Response($body, 500);
        }

        public function addSecurityHeaders(array $overrides = []): void {
            $headers = [
                'X-Frame-Options' => 'DENY',
                'X-Content-Type-Options' => 'nosniff',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
                'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
                'Content-Security-Policy' => "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            ];
            foreach ($overrides as $name => $value) {
                $headers[$name] = $value;
            }

            $this->addMiddleware(function (Request $req, callable $next) use ($headers): Response {
                $response = $next($req);
                $finalHeaders = $headers;
                if (!array_key_exists('Strict-Transport-Security', $finalHeaders) && $this->isHttps($req)) {
                    $finalHeaders['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload';
                }

                foreach ($finalHeaders as $name => $value) {
                    if ($value === null) {
                        continue;
                    }
                    $exists = false;
                    foreach ($response->headers as $key => $_) {
                        if (strcasecmp((string) $key, (string) $name) === 0) {
                            $exists = true;
                            break;
                        }
                    }
                    if (!$exists) {
                        $response->headers[$name] = $value;
                    }
                }

                return $response;
            });
        }

        private function isHttps(Request $request): bool {
            $https = strtolower((string) ($request->server['HTTPS'] ?? ''));
            if ($https !== '' && $https !== 'off') {
                return true;
            }
            if (!$this->isFromTrustedProxy($request)) {
                return false;
            }
            return strtolower((string) ($request->header('X-Forwarded-Proto') ?? '')) === 'https';
        }

        private function isFromTrustedProxy(Request $request): bool {
            $trusted = $this->config('trusted_proxies', []);
            if (!is_array($trusted) || $trusted === []) {
                return false;
            }
            $remote = (string) ($request->server['REMOTE_ADDR'] ?? '');
            return $remote !== '' && in_array($remote, $trusted, true);
        }

        private function withErrorHandler(callable $callback): Response {
            set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
                if (error_reporting() === 0) {
                    return false;
                }
                $alwaysThrow = [E_WARNING, E_USER_WARNING, E_RECOVERABLE_ERROR, E_USER_ERROR];
                if (!in_array($severity, $alwaysThrow, true) && !(error_reporting() & $severity)) {
                    return false;
                }
                throw new \ErrorException($message, 0, $severity, $file, $line);
            });

            try {
                return $callback();
            } finally {
                restore_error_handler();
            }
        }

        private function registerErrorHandlers(): void {
            if (self::$shutdownRegistered) {
                return;
            }

            register_shutdown_function(function (): void {
                $error = error_get_last();
                if ($error === null) {
                    return;
                }
                if (!in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
                    return;
                }

                Log::error('Fatal error', [
                    'message' => (string) ($error['message'] ?? ''),
                    'file' => (string) ($error['file'] ?? ''),
                    'line' => (int) ($error['line'] ?? 0),
                ]);

                $debug = (int) (self::$instance?->config('debug', 0) ?? 0);
                $body = $debug >= 3
                    ? (string) $error['message'] . ' in ' . (string) $error['file'] . ':' . (int) $error['line']
                    : 'Wystąpił błąd serwera.';

                if (!headers_sent()) {
                    http_response_code(500);
                    header('Content-Type: text/plain; charset=UTF-8');
                }
                echo $body;
            });

            self::$shutdownRegistered = true;
        }

        public function run(): void {
            $trusted = $this->config('trusted_proxies', []);
            if (!is_array($trusted)) {
                $trusted = [];
            }
            $request = Request::fromGlobalsWithProxies($trusted);
            $response = $this->handle($request);
            $response->send();
        }
    }

    class Db {
        private \PDO $pdo;

        /** @var array<int, array{sql: string, time: float}> */
        private array $log = [];
        private bool $logQueries;

        public function __construct(array $config) {
            $dsn = $config['dsn'] ?? sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                $config['host'] ?? 'localhost',
                (int) ($config['port'] ?? 3306),
                $config['name'] ?? '',
            );

            $this->pdo = new \PDO(
                $dsn,
                $config['user'] ?? null,
                $config['pass'] ?? null,
                [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                    \PDO::ATTR_EMULATE_PREPARES => false,
                ],
            );
            $this->logQueries = (bool) ($config['log_queries'] ?? false);
        }

        public function pdo(): \PDO {
            return $this->pdo;
        }

        private function norm(array|string|null $params): ?array {
            if (is_string($params)) {
                return [$params];
            }
            return $params;
        }

        private function run(string $sql, array|string|null $params): \PDOStatement {
            $t = microtime(true);
            $norm = $this->norm($params);
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($norm);
            if ($this->logQueries) {
                $this->log[] = ['sql' => $this->interpolate($sql, $norm), 'time' => microtime(true) - $t];
            }
            return $stmt;
        }

        private function interpolate(string $sql, ?array $params): string {
            if ($params === null || $params === []) {
                return $sql;
            }
            $i = 0;
            return preg_replace_callback('/\?/', function () use ($params, &$i): string {
                $v = $params[$i++] ?? 'NULL';
                if ($v === null) {
                    return 'NULL';
                }
                if (is_int($v) || is_float($v)) {
                    return (string) $v;
                }
                return "'" . addslashes((string) $v) . "'";
            }, $sql);
        }

        /** @return array<int, array{sql: string, time: float}> */
        public function queryLog(): array {
            return $this->log;
        }

        public function queryCount(): int {
            return count($this->log);
        }

        public function queryTime(): float {
            return array_sum(array_column($this->log, 'time'));
        }

        public function exec(string $sql, array|string|null $params = null): int|array {
            $stmt = $this->run($sql, $params);
            if ($this->isSelectQuery($sql)) {
                return $stmt->fetchAll();
            }
            return $stmt->rowCount();
        }

        public function var(string $sql, array|string|null $params = null): mixed {
            $row = $this->run($sql, $params)->fetch(\PDO::FETCH_NUM);
            return $row ? $row[0] : null;
        }

        public function row(string $sql, array|string|null $params = null): ?array {
            $row = $this->run($sql, $params)->fetch();
            return $row ?: null;
        }

        public function results(string $sql, array|string|null $params = null): array {
            return $this->run($sql, $params)->fetchAll();
        }

        public function col(string $sql, array|string|null $params = null): array {
            return $this->run($sql, $params)->fetchAll(\PDO::FETCH_COLUMN);
        }

        public function insertGetId(string $sql, array|string|null $params = null): int {
            $this->run($sql, $params);
            return (int) $this->pdo->lastInsertId();
        }

        public function begin(): bool {
            return $this->pdo->beginTransaction();
        }

        public function commit(): bool {
            return $this->pdo->commit();
        }

        public function rollback(): bool {
            return $this->pdo->rollBack();
        }

        public function placeholders(array $items): string {
            return implode(', ', array_fill(0, count($items), '?'));
        }

        private function isSelectQuery(string $sql): bool {
            $sql = $this->stripLeadingComments($sql);
            if ($sql === '') {
                return false;
            }
            if (preg_match('/^(SELECT|PRAGMA|SHOW|DESCRIBE|EXPLAIN)\b/i', $sql)) {
                return true;
            }
            if (!preg_match('/^WITH\b/i', $sql)) {
                return false;
            }
            $statement = $this->statementAfterWith($sql);
            return $statement !== null && in_array($statement, ['SELECT', 'PRAGMA', 'SHOW', 'DESCRIBE', 'EXPLAIN'], true);
        }

        private function stripLeadingComments(string $sql): string {
            $s = ltrim($sql);
            while (true) {
                if (str_starts_with($s, '--')) {
                    $pos = strpos($s, "\n");
                    if ($pos === false) {
                        return '';
                    }
                    $s = ltrim(substr($s, $pos + 1));
                    continue;
                }
                if (str_starts_with($s, '#')) {
                    $pos = strpos($s, "\n");
                    if ($pos === false) {
                        return '';
                    }
                    $s = ltrim(substr($s, $pos + 1));
                    continue;
                }
                if (str_starts_with($s, '/*')) {
                    $pos = strpos($s, '*/');
                    if ($pos === false) {
                        return '';
                    }
                    $s = ltrim(substr($s, $pos + 2));
                    continue;
                }
                break;
            }
            return $s;
        }

        private function statementAfterWith(string $sql): ?string {
            $len = strlen($sql);
            $offset = 0;
            if (preg_match('/^\s*WITH\b/i', $sql, $match)) {
                $offset = strlen($match[0]);
            }

            $depth = 0;
            $seenCte = false;
            $inSingle = false;
            $inDouble = false;
            $inBacktick = false;

            for ($i = $offset; $i < $len; $i++) {
                $ch = $sql[$i];
                if ($inSingle) {
                    if ($ch === "'" && ($i === 0 || $sql[$i - 1] !== '\\')) {
                        $inSingle = false;
                    }
                    continue;
                }
                if ($inDouble) {
                    if ($ch === '"' && ($i === 0 || $sql[$i - 1] !== '\\')) {
                        $inDouble = false;
                    }
                    continue;
                }
                if ($inBacktick) {
                    if ($ch === '`') {
                        $inBacktick = false;
                    }
                    continue;
                }

                if ($ch === "'") {
                    $inSingle = true;
                    continue;
                }
                if ($ch === '"') {
                    $inDouble = true;
                    continue;
                }
                if ($ch === '`') {
                    $inBacktick = true;
                    continue;
                }
                if ($ch === '(') {
                    $depth++;
                    continue;
                }
                if ($ch === ')') {
                    if ($depth > 0) {
                        $depth--;
                    }
                    if ($depth === 0) {
                        $seenCte = true;
                    }
                    continue;
                }

                if ($seenCte && $depth === 0 && $ch === ',') {
                    $seenCte = false;
                    continue;
                }

                if ($seenCte && $depth === 0 && ctype_alpha($ch)) {
                    $start = $i;
                    while ($i < $len && ctype_alpha($sql[$i])) {
                        $i++;
                    }
                    $word = strtoupper(substr($sql, $start, $i - $start));
                    if ($word === 'RECURSIVE' || $word === 'AS') {
                        $seenCte = false;
                        continue;
                    }
                    return $word;
                }
            }

            return null;
        }
    }

    class View {
        private ?string $layoutFile = null;

        private array $layoutData = [];

        public function __construct(private readonly string $basePath) {
        }

        public function render(string $template, array $data = []): string {
            $this->layoutFile = null;
            $this->layoutData = [];

            $content = $this->renderFile($template, $data);
            if ($this->layoutFile !== null) {
                $layoutFile = $this->layoutFile;
                $layoutData = array_merge($data, $this->layoutData, ['content' => $content]);
                $this->layoutFile = null;
                $content = $this->renderFile($layoutFile, $layoutData);
            }
            return $content;
        }

        public function layout(string $file, array $data = []): void {
            $this->layoutFile = $file;
            $this->layoutData = $data;
        }

        public function partial(string $template, array $data = []): string {
            return $this->renderFile($template, $data);
        }

        private function renderFile(string $template, array $data): string {
            $filePath = rtrim($this->basePath, '/') . '/' . ltrim($template, '/');
            $realBase = realpath($this->basePath);
            $realFile = realpath($filePath);
            if ($realFile === false || $realBase === false || !str_starts_with($realFile, $realBase . '/')) {
                throw new \RuntimeException('Template not found: ' . $template);
            }

            $view = $this;
            extract($data, EXTR_SKIP);

            ob_start();
            include $filePath;
            return (string) ob_get_clean();
        }
    }

    class Session implements \SessionHandlerInterface {
        private ?string $lockName = null;

        public function __construct(
            private readonly Db $db,
            private readonly bool $advisory = true,
        ) {
        }

        public function register(array $cookieParams = []): void {
            session_set_save_handler($this, true);
            $defaults = [
                'lifetime' => 7200,
                'path' => '/',
                'domain' => '',
                'secure' => false,
                'httponly' => true,
                'samesite' => 'Lax',
            ];
            $params = array_merge($defaults, $cookieParams);

            $ini = [
                'session.use_strict_mode' => '1',
                'session.use_only_cookies' => '1',
                'session.use_trans_sid' => '0',
                'session.sid_length' => '64',
                'session.sid_bits_per_character' => '6',
                'session.cookie_httponly' => $params['httponly'] ? '1' : '0',
                'session.cookie_secure' => $params['secure'] ? '1' : '0',
                'session.cookie_samesite' => (string) $params['samesite'],
                'session.gc_maxlifetime' => (string) $params['lifetime'],
            ];
            foreach ($ini as $key => $value) {
                @ini_set($key, $value);
            }

            session_set_cookie_params($params);
        }

        public function regenerate(bool $deleteOld = true): bool {
            return session_regenerate_id($deleteOld);
        }

        public function open(string $path, string $name): bool {
            return true;
        }

        public function read(string $id): string|false {
            if ($this->advisory) {
                $this->acquireLock($id);
            }

            try {
                $data = $this->db->var('SELECT data FROM sessions WHERE session_id = ?', [$id]);
                return is_string($data) ? $data : '';
            } catch (\Throwable $e) {
                $this->releaseLock();
                throw $e;
            }
        }

        public function write(string $id, string $data): bool {
            try {
                $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
                $agent = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 5000);
                $stamp = time();

                $driver = (string) $this->db->pdo()->getAttribute(\PDO::ATTR_DRIVER_NAME);
                if ($driver === 'sqlite') {
                    $this->db->exec(
                        'INSERT OR REPLACE INTO sessions (session_id, data, ip, agent, stamp) VALUES (?, ?, ?, ?, ?)',
                        [$id, $data, $ip, $agent, $stamp],
                    );
                } else {
                    $this->db->exec(
                        'INSERT INTO sessions (session_id, data, ip, agent, stamp) VALUES (?, ?, ?, ?, ?) '
                        . 'ON DUPLICATE KEY UPDATE data=VALUES(data), ip=VALUES(ip), agent=VALUES(agent), stamp=VALUES(stamp)',
                        [$id, $data, $ip, $agent, $stamp],
                    );
                }
            } finally {
                $this->releaseLock();
            }

            return true;
        }

        public function close(): bool {
            $this->releaseLock();
            return true;
        }

        public function destroy(string $id): bool {
            $this->db->exec('DELETE FROM sessions WHERE session_id = ?', [$id]);
            $this->releaseLock();
            return true;
        }

        public function gc(int $max_lifetime): int|false {
            return $this->db->exec('DELETE FROM sessions WHERE stamp < ?', [time() - $max_lifetime]);
        }

        private function acquireLock(string $id): void {
            $this->lockName = 'sess_' . substr($id, 0, 32);
            try {
                if ($this->db->pdo()->inTransaction()) {
                    $this->db->pdo()->rollBack();
                }
                $this->db->var('SELECT GET_LOCK(?, 10)', [$this->lockName]);
            } catch (\Throwable) {
                $this->lockName = null;
            }
        }

        private function releaseLock(): void {
            if ($this->lockName === null) {
                return;
            }

            try {
                $this->db->var('SELECT RELEASE_LOCK(?)', [$this->lockName]);
            } catch (\Throwable) {
                // Ignore release errors for non-MySQL drivers.
            }

            $this->lockName = null;
        }
    }

    class Csrf {
        private const SESSION_KEY = '_csrf_token';

        private const SECRET_KEY = '_csrf_secret';

        public const FIELD_NAME = 'csrf_token';

        public static function token(): string {
            if (empty($_SESSION[self::SESSION_KEY])) {
                $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
            }

            return (string) $_SESSION[self::SESSION_KEY];
        }

        public static function validate(?string $token): bool {
            if ($token === null || $token === '') {
                return false;
            }

            $stored = (string) ($_SESSION[self::SESSION_KEY] ?? '');
            if ($stored === '') {
                return false;
            }

            return hash_equals($stored, $token);
        }

        public static function nonce(string $action): string {
            if (empty($_SESSION[self::SECRET_KEY])) {
                $_SESSION[self::SECRET_KEY] = bin2hex(random_bytes(32));
            }

            return hash_hmac('sha256', $action, (string) $_SESSION[self::SECRET_KEY]);
        }

        public static function verifyNonce(string $action, ?string $token): bool {
            if ($token === null || $token === '') {
                return false;
            }

            return hash_equals(self::nonce($action), $token);
        }

        public static function hiddenInput(?string $action = null): string {
            $token = $action !== null ? self::nonce($action) : self::token();
            $escaped = htmlspecialchars($token, ENT_QUOTES, 'UTF-8');
            return '<input type="hidden" name="' . self::FIELD_NAME . '" value="' . $escaped . '">';
        }
    }

    class Flash {
        private const SESSION_KEY = '_flash_messages';

        public function add(string $type, string $text): void {
            $_SESSION[self::SESSION_KEY][] = ['type' => $type, 'text' => $text];
        }

        public function get(): array {
            $messages = $_SESSION[self::SESSION_KEY] ?? [];
            unset($_SESSION[self::SESSION_KEY]);
            return $messages;
        }

        public function has(): bool {
            return !empty($_SESSION[self::SESSION_KEY]);
        }

        public function success(string $text): void {
            $this->add('success', $text);
        }

        public function error(string $text): void {
            $this->add('error', $text);
        }

        public function warning(string $text): void {
            $this->add('warning', $text);
        }

        public function info(string $text): void {
            $this->add('info', $text);
        }
    }

    abstract class Controller {
        public Request $request;

        protected function render(string $template, array $data = []): Response {
            $app = App::instance();
            $viewPath = (string) $app->config('view_path', 'templates');
            $view = new View($viewPath);

            $data['flash'] = (new Flash())->get();
            $data['csrf_token'] = Csrf::token();
            $data['csrf_input'] = Csrf::hiddenInput();
            $data['url'] = static fn(string $name, array $params = []): string => $app->url($name, $params);

            return Response::html($view->render($template, $data));
        }

        protected function json(mixed $data, int $status = 200): Response {
            return Response::json($data, $status);
        }

        protected function jsonSuccess(array $data = []): Response {
            return Response::json(array_merge(['success' => true], $data));
        }

        protected function jsonError(string $message, int $status = 400, array $extra = []): Response {
            return Response::json(array_merge(['success' => false, 'message' => $message], $extra), $status);
        }

        protected function flash(string $type, string $message): void {
            (new Flash())->add($type, $message);
        }

        protected function redirect(string $url, int $status = 302): Response {
            return Response::redirect($url, $status);
        }

        protected function flashAndRedirect(string $type, string $message, string $url): Response {
            $this->flash($type, $message);
            return $this->redirect($url);
        }

        protected function requireAuth(): void {
            if (!$this->currentUser()) {
                $this->flash('warning', 'Musisz się zalogować.');
                throw HttpException::unauthorized();
            }
        }

        protected function requireAdmin(): void {
            $this->requireAuth();
            if (($this->currentUser()['role'] ?? '') !== 'admin') {
                throw HttpException::forbidden();
            }
        }

        protected function currentUser(): ?array {
            return $_SESSION['user'] ?? null;
        }

        protected function currentUserId(): int {
            return (int) ($this->currentUser()['id'] ?? 0);
        }

        protected function isAuthenticated(): bool {
            return $this->currentUser() !== null;
        }

        protected function validateCsrf(): void {
            $token = $this->request->post(Csrf::FIELD_NAME) ?? $this->request->header('X-Csrf-Token');
            if (!Csrf::validate($token)) {
                throw HttpException::forbidden('Sesja wygasła. Odśwież stronę.');
            }
        }

        protected function param(string $key, mixed $default = null): mixed {
            return $this->request->param($key, $default);
        }

        protected function postData(array $keys): array {
            return $this->request->only($keys);
        }

        protected function paginate(int $total, int $perPage = 20): array {
            $perPage = max(1, $perPage);
            $page = max(1, (int) ($this->request->query('page') ?? 1));
            $totalPages = max(1, (int) ceil($total / $perPage));
            $page = min($page, $totalPages);
            $offset = ($page - 1) * $perPage;

            return [
                'page' => $page,
                'offset' => $offset,
                'total_pages' => $totalPages,
                'per_page' => $perPage,
                'total' => $total,
            ];
        }
    }

    class Log {
        private const LEVELS = [
            'trace' => 1,
            'debug' => 3,
            'info' => 5,
            'warn' => 7,
            'error' => 9,
        ];

        private static ?string $basePath = null;

        private static int $minLevel = 5;

        public static function init(string $basePath, int $minLevel = 5): void {
            self::$basePath = rtrim($basePath, '/');
            self::$minLevel = $minLevel;
        }

        public static function trace(string $msg, array $ctx = []): void {
            self::log('trace', $msg, $ctx);
        }

        public static function debug(string $msg, array $ctx = []): void {
            self::log('debug', $msg, $ctx);
        }

        public static function info(string $msg, array $ctx = []): void {
            self::log('info', $msg, $ctx);
        }

        public static function warn(string $msg, array $ctx = []): void {
            self::log('warn', $msg, $ctx);
        }

        public static function error(string $msg, array $ctx = []): void {
            self::log('error', $msg, $ctx);
        }

        public static function toFile(string $filename, string $message): void {
            if (self::$basePath === null) {
                return;
            }

            if (!is_dir(self::$basePath)) {
                @mkdir(self::$basePath, 0755, true);
            }

            $path = self::$basePath . '/' . date('Y') . '_' . $filename;
            @file_put_contents($path, date('[Y-m-d H:i:s] ') . $message . "\n", FILE_APPEND | LOCK_EX);
        }

        private static function log(string $level, string $msg, array $ctx): void {
            if ((self::LEVELS[$level] ?? 9) < self::$minLevel) {
                return;
            }

            $line = strtoupper($level) . ' ' . $msg;
            if ($ctx !== []) {
                $line .= ' ' . json_encode($ctx, JSON_UNESCAPED_UNICODE);
            }

            self::toFile('app.log', $line);
        }
    }

    class Validator {
        public static function email(string $value): bool {
            return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
        }

        public static function phone(string $value): bool {
            $normalized = preg_replace('/[\s\-]/', '', $value);
            return (bool) preg_match('/^(\+48)?[0-9]{9}$/', (string) $normalized);
        }

        public static function postcode(string $value): bool {
            return (bool) preg_match('/^[0-9]{2}-[0-9]{3}$/', $value);
        }

        public static function length(string $value, int $min, int $max): ?string {
            $len = mb_strlen($value);
            if ($len < $min) {
                return 'Minimum ' . $min . ' znaków';
            }
            if ($len > $max) {
                return 'Maksimum ' . $max . ' znaków';
            }
            return null;
        }

        public static function required(mixed $value): bool {
            return $value !== null && $value !== '';
        }

        public static function intRange(mixed $value, int $min, int $max): bool {
            if (is_int($value)) {
                return $value >= $min && $value <= $max;
            }
            if (!is_scalar($value) || !is_numeric((string) $value)) {
                return false;
            }
            $int = (int) $value;
            return $int >= $min && $int <= $max;
        }

        public static function slug(string $value, int $maxLength = 100): ?string {
            if (mb_strlen($value) > $maxLength) {
                return 'Slug max ' . $maxLength . ' znaków';
            }
            if (!preg_match('/^[a-z0-9-]+$/', $value)) {
                return 'Slug: tylko małe litery, cyfry i myślniki';
            }
            return null;
        }

        public static function validate(array $rules, array $data): array {
            $errors = [];
            foreach ($rules as $field => $fieldRules) {
                $value = $data[$field] ?? null;
                foreach ((array) $fieldRules as $rule) {
                    $error = match (true) {
                        $rule === 'required' && !self::required($value) => 'Pole wymagane',
                        $rule === 'email' && is_string($value) && !self::email($value) => 'Nieprawidłowy email',
                        $rule === 'phone' && is_string($value) && !self::phone($value) => 'Nieprawidłowy telefon',
                        $rule === 'postcode' && is_string($value) && !self::postcode($value) => 'Format: XX-XXX',
                        default => null,
                    };

                    if ($error !== null) {
                        $errors[$field] = $error;
                        break;
                    }
                }
            }

            return $errors;
        }
    }

    class Cache {
        public function __construct(private readonly string $dir) {
            if (!is_dir($this->dir)) {
                mkdir($this->dir, 0755, true);
            }
        }

        public function get(string $key, mixed $default = null): mixed {
            if (function_exists('apcu_exists') && apcu_exists($key)) {
                return apcu_fetch($key);
            }

            $path = $this->path($key);
            if (!is_file($path)) {
                return $default;
            }

            $serialized = file_get_contents($path);
            if ($serialized === false) {
                return $default;
            }

            try {
                $data = @unserialize($serialized, ['allowed_classes' => false]);
            } catch (\Throwable) {
                @unlink($path);
                return $default;
            }

            if (!is_array($data) || !array_key_exists('value', $data) || !isset($data['ttl'], $data['time'])) {
                @unlink($path);
                return $default;
            }

            if ($data['ttl'] > 0 && ((int) $data['time'] + (int) $data['ttl']) < time()) {
                @unlink($path);
                return $default;
            }

            return $data['value'];
        }

        public function set(string $key, mixed $value, int $ttl = 0): void {
            if (function_exists('apcu_store') && $ttl > 0) {
                apcu_store($key, $value, $ttl);
            }

            file_put_contents(
                $this->path($key),
                serialize(['value' => $value, 'ttl' => $ttl, 'time' => time()]),
                LOCK_EX,
            );
        }

        public function delete(string $key): void {
            if (function_exists('apcu_delete')) {
                apcu_delete($key);
            }

            $path = $this->path($key);
            if (is_file($path)) {
                unlink($path);
            }
        }

        public function clear(): void {
            foreach (glob($this->dir . '/*.cache') ?: [] as $file) {
                unlink($file);
            }
        }

        public function rateCheck(string $scope, string $id, int $max, int $window): ?int {
            $key = 'rl:' . $scope . ':' . $id;
            $data = $this->get($key);
            if (!is_array($data)) {
                $this->set($key, ['count' => 1, 'start' => time()], $window);
                return null;
            }

            $elapsed = time() - (int) ($data['start'] ?? 0);
            if ($elapsed >= $window) {
                $this->set($key, ['count' => 1, 'start' => time()], $window);
                return null;
            }

            if ((int) ($data['count'] ?? 0) >= $max) {
                return $window - $elapsed;
            }

            $data['count'] = (int) ($data['count'] ?? 0) + 1;
            $this->set($key, $data, $window);
            return null;
        }

        private function path(string $key): string {
            return $this->dir . '/' . md5($key) . '.cache';
        }
    }

    class Base {
        public static function app(): App {
            return App::instance();
        }

        public static function config(string $key, mixed $default = null): mixed {
            return self::app()->config($key, $default);
        }

        public static function db(): Db {
            return self::app()->db();
        }

        public static function url(string $name, array $params = []): string {
            return self::app()->url($name, $params);
        }

        public static function var(string $sql, array|string|null $params = null): mixed {
            return self::db()->var($sql, $params);
        }

        public static function row(string $sql, array|string|null $params = null): ?array {
            return self::db()->row($sql, $params);
        }

        public static function results(string $sql, array|string|null $params = null): array {
            return self::db()->results($sql, $params);
        }

        public static function col(string $sql, array|string|null $params = null): array {
            return self::db()->col($sql, $params);
        }

        public static function exec(string $sql, array|string|null $params = null): int|array {
            return self::db()->exec($sql, $params);
        }

        public static function insertGetId(string $sql, array|string|null $params = null): int {
            return self::db()->insertGetId($sql, $params);
        }

        public static function flash(): Flash {
            return new Flash();
        }
    }
}

namespace {
    function h(mixed $value): string {
        if ($value === null || (!is_scalar($value) && !$value instanceof \Stringable)) {
            return '';
        }

        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    function ha(array $array, string|int $key, mixed $default = ''): string {
        return h($array[$key] ?? $default);
    }

    function getS(?array $array, string|int $key, mixed $default = null): mixed {
        if ($array === null) {
            return $default;
        }

        return $array[$key] ?? $default;
    }

    function strlenS(?string $s): int {
        return mb_strlen($s ?? '');
    }

    function substrS(?string $s, int $start, ?int $length = null): string {
        return mb_substr($s ?? '', $start, $length);
    }

    function trimS(mixed $value, string $characters = " \n\r\t\v\x00"): string {
        if ($value === null) {
            return '';
        }

        return trim((string) $value, $characters);
    }

    function strtotimeS(mixed $date): int|false {
        if ($date === null || $date === '') {
            return false;
        }

        return strtotime((string) $date);
    }

    function strip_tagsS(mixed $s): string {
        return trim(strip_tags((string) ($s ?? '')));
    }

    function countS(mixed $value): int {
        if ($value === null) {
            return 0;
        }
        if (is_array($value) || $value instanceof \Countable) {
            return count($value);
        }
        return 0;
    }

    function explodeS(string $separator, mixed $string, int $limit = PHP_INT_MAX): array {
        if ($string === null || $string === '' || $string === []) {
            return [];
        }
        if (!is_scalar($string) && !$string instanceof \Stringable) {
            return [];
        }

        return array_map('trim', explode($separator, (string) $string, $limit));
    }
}
