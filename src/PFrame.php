<?php
/**
 * PFrame — PHP 8.4+ micro-framework
 * Single-file, zero dependencies
 *
 * Usage: require 'PFrame.php'; class P1 extends \PFrame\Base {}
 */
declare(strict_types=1);

namespace PFrame {

    /** @phpstan-consistent-constructor */
    class HttpException extends \RuntimeException {
        /** @param array<string, string> $headers */
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

        /** @param list<string> $allowed */
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

    /** @phpstan-consistent-constructor */
    class Request {
        /** @var array<string, mixed> */
        private array $params = [];
        /** @var array<string, string> */
        public readonly array $headers;
        private bool $jsonBodyParsed = false;
        /** @var array<string, mixed>|null */
        private ?array $jsonBodyCache = null;

        /**
         * @param array<string, mixed> $query
         * @param array<string, mixed> $post
         * @param array<string, mixed> $server
         * @param array<string, string> $headers
         * @param array<string, mixed> $cookies
         * @param array<string, mixed> $files
         */
        public function __construct(
            public readonly string $method,
            public readonly string $path,
            public readonly array $query = [],
            public readonly array $post = [],
            public readonly array $server = [],
            array $headers = [],
            public readonly array $cookies = [],
            public readonly array $files = [],
            public readonly string $ip = '',
            public readonly string $body = '',
        ) {
            $normalized = [];
            foreach ($headers as $k => $v) {
                $normalized[ucwords(strtolower((string) $k), '-')] = (string) $v;
            }
            $this->headers = $normalized;
        }

        public static function fromGlobals(): static {
            return self::buildFromGlobals((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        }

        /** @param list<string> $trustedProxies */
        public static function fromGlobalsWithProxies(array $trustedProxies = []): static {
            $headers = self::parseServerHeaders($_SERVER);
            return self::buildFromGlobals(self::resolveIp($_SERVER, $headers, $trustedProxies), $headers);
        }

        /** @param array<string, string>|null $headers */
        private static function buildFromGlobals(string $ip, ?array $headers = null): static {
            $uri = $_SERVER['REQUEST_URI'] ?? '/';
            $path = parse_url($uri, PHP_URL_PATH) ?: '/';
            $headers ??= self::parseServerHeaders($_SERVER);

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

        /**
         * @param array<string, mixed> $server
         * @return array<string, string>
         */
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

        /**
         * @param array<string, mixed> $server
         * @param array<string, string> $headers
         * @param list<string> $trustedProxies
         */
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
            return $this->headers[ucwords(strtolower($name), '-')] ?? $default;
        }

        public function param(string $key, mixed $default = null): mixed {
            return $this->params[$key] ?? $default;
        }

        /** @param array<string, mixed> $params */
        public function setParams(array $params): void {
            $this->params = $params;
        }

        /**
         * @param list<string> $keys
         * @return array<string, mixed>
         */
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

        /** @return array<string|int, mixed>|null */
        public function jsonBody(): ?array {
            if ($this->jsonBodyParsed) {
                return $this->jsonBodyCache;
            }

            $this->jsonBodyParsed = true;
            if ($this->body === '') {
                return null;
            }

            $decoded = json_decode($this->body, true);
            $this->jsonBodyCache = is_array($decoded) ? $decoded : null;
            return $this->jsonBodyCache;
        }
    }

    /** @phpstan-consistent-constructor */
    class Response {
        /** @param array<string, string> $headers */
        public function __construct(
            public string $body = '',
            public int $status = 200,
            public array $headers = [],
            public ?string $filePath = null,
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
            $url = ltrim($url, " \t\n\r\0\x0B");

            if (str_contains($url, '\\')) {
                throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
            }

            if (str_starts_with($url, '//')) {
                throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
            }

            if (!str_starts_with($url, '/')) {
                $scheme = parse_url($url, PHP_URL_SCHEME);
                if (is_string($scheme)) {
                    if (!in_array(strtolower($scheme), ['http', 'https'], true)) {
                        throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
                    }
                    if (!preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $url)) {
                        throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
                    }
                }

                $host = parse_url($url, PHP_URL_HOST);
                if (is_string($host)) {
                    $currentHost = (string) ($_SERVER['HTTP_HOST'] ?? '');
                    if ($currentHost === '') {
                        throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
                    }
                    $normalizedCurrentHost = (string) (parse_url('http://' . $currentHost, PHP_URL_HOST) ?? $currentHost);
                    if (strcasecmp($host, $normalizedCurrentHost) !== 0) {
                        throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
                    }
                }
            }
            return new static('', $status, ['Location' => $url]);
        }

        /** @param array<string, string> $headers */
        public static function file(string $path, array $headers = [], int $status = 200): static {
            return new static('', $status, $headers, $path);
        }

        public function send(): void {
            http_response_code($this->status);
            foreach ($this->headers as $name => $value) {
                header($name . ': ' . $value);
            }
            if ($this->filePath !== null) {
                readfile($this->filePath);
                return;
            }
            echo $this->body;
        }

        public function sendAndExit(): never {
            $this->send();
            exit;
        }
    }

    class SseResponse extends Response {
        private \Closure $callback;

        /**
         * Keep Response constructor compatibility while requiring a callback.
         *
         * @param mixed $body
         * @param array<string, string> $headers
         */
        public function __construct(mixed $body = '', int $status = 200, array $headers = [], ?string $filePath = null) {
            if (!$body instanceof \Closure) {
                throw new \InvalidArgumentException('SseResponse requires callback closure as first argument.');
            }

            parent::__construct('', $status, array_merge([
                'Content-Type' => 'text/event-stream',
                'Cache-Control' => 'no-cache',
                'Connection' => 'keep-alive',
                'X-Accel-Buffering' => 'no',
            ], $headers), $filePath);
            $this->callback = $body;
        }

        public static function json(mixed $data, int $status = 200): static {
            throw new \LogicException('SseResponse does not support json(). Use the callback to send SSE events.');
        }

        public static function html(string $body, int $status = 200): static {
            throw new \LogicException('SseResponse does not support html(). Use the callback to send SSE events.');
        }

        public static function file(string $path, array $headers = [], int $status = 200): static {
            throw new \LogicException('SseResponse does not support file(). Use the callback to send SSE events.');
        }

        public static function redirect(string $url, int $status = 302): static {
            throw new \LogicException('SseResponse does not support redirect(). Use the callback to send SSE events.');
        }

        public function send(): void {
            http_response_code($this->status);
            foreach ($this->headers as $name => $value) {
                header($name . ': ' . $value);
            }
            ($this->callback)();
        }
    }

    /** @phpstan-consistent-constructor */
    class App {
        private static ?self $instance = null;
        private static bool $shutdownRegistered = false;

        /** @var array<string, mixed> */
        private array $configData = [];

        /** @var array<int, array{methods: list<string>, pattern: string, regex: string, paramNames: list<string>, controller: string, action: string, middleware: array<callable>, name: ?string, ajax: bool}> */
        private array $routes = [];

        /** @var array<string, array<int, int>> */
        private array $routesByMethod = [];

        /** @var array<string, array<string, array<int, int>>> */
        private array $staticRoutesByMethod = [];

        /** @var array<string, int> */
        private array $namedRoutes = [];

        /** @var array<string, array{invoke_without_args: bool, arg_types: array<int, string>}> */
        private array $methodCallPlanCache = [];

        /** @var array<callable> */
        private array $middleware = [];

        private const HTTP_STATUS_TEXT = [
            400 => 'Bad Request',
            401 => 'Unauthorized',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            408 => 'Request Timeout',
            422 => 'Unprocessable Entity',
            429 => 'Too Many Requests',
            500 => 'Internal Server Error',
            502 => 'Bad Gateway',
            503 => 'Service Unavailable',
        ];

        /** @var (callable(HttpException, Request, App): ?Response)|null */
        private $errorPageHandler = null;

        /** @var array<int, array{prefix: string, middleware: array<callable>, name_prefix: string}> */
        private array $routeGroups = [['prefix' => '', 'middleware' => [], 'name_prefix' => '']];

        private ?Db $db = null;
        private ?View $lastView = null;

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
            if (!self::$instance instanceof static) {
                throw new \LogicException('App instance already initialized as ' . self::$instance::class . ', requested ' . static::class . '.');
            }
            /** @var static $instance */
            $instance = self::$instance;
            return $instance;
        }

        public function resetRequestState(): void {
            $this->startTime = microtime(true);
            $this->lastView = null;
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

        public function dbIfInitialized(): ?Db {
            return $this->db;
        }

        public function setDb(Db $db): void {
            $this->db = $db;
        }

        public function lastView(): ?View {
            return $this->lastView;
        }

        public function setLastView(View $view): void {
            $this->lastView = $view;
        }

        /** @param callable(HttpException, Request, self): ?Response $handler */
        public function setErrorPageHandler(callable $handler): void {
            $this->errorPageHandler = $handler;
        }

        /** @param array<callable> $mw */
        public function get(string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void {
            $this->addRoute('GET|HEAD', $path, $controller, $action, $mw, $name, $ajax);
        }

        /** @param array<callable> $mw */
        public function post(string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void {
            $this->addRoute('POST', $path, $controller, $action, $mw, $name, $ajax);
        }

        /** @param array<callable> $mw */
        public function route(string $methods, string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void {
            $this->addRoute($methods, $path, $controller, $action, $mw, $name, $ajax);
        }

        /**
         * @param callable(self): void $callback
         * @param array<callable> $mw
         */
        public function group(string $prefix, callable $callback, array $mw = [], ?string $namePrefix = null): void {
            $group = $this->currentRouteGroup();
            $this->routeGroups[] = [
                'prefix' => $this->joinRoutePath($group['prefix'], $prefix),
                'middleware' => array_merge($group['middleware'], $mw),
                'name_prefix' => $group['name_prefix'] . ($namePrefix ?? ''),
            ];

            try {
                $callback($this);
            } finally {
                array_pop($this->routeGroups);
            }
        }

        /** @param array<callable> $middleware */
        private function addRoute(
            string $methods,
            string $pattern,
            string $controller,
            string $action,
            array $middleware,
            ?string $name,
            bool $ajax,
        ): void {
            $group = $this->currentRouteGroup();
            $pattern = $this->joinRoutePath($group['prefix'], $pattern);
            $middleware = array_merge($group['middleware'], $middleware);
            if ($name !== null && $group['name_prefix'] !== '') {
                $name = $group['name_prefix'] . $name;
            }
            if ($name !== null && isset($this->namedRoutes[$name])) {
                throw new \RuntimeException('Duplicate route name: ' . $name);
            }

            $methodList = array_values(array_filter(array_map('trim', explode('|', strtoupper($methods)))));
            $paramNames = [];
            $parts = preg_split('/(\{\w+\}|\*)/', $pattern, -1, PREG_SPLIT_DELIM_CAPTURE);
            if ($parts === false) {
                throw new \RuntimeException('Failed to parse route pattern: ' . $pattern);
            }
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

            foreach ($methodList as $method) {
                $this->routesByMethod[$method][] = $index;
            }

            if (!str_contains($pattern, '{') && !str_contains($pattern, '*')) {
                $normalizedPattern = $this->normalizeStaticPath($pattern);
                foreach ($methodList as $method) {
                    $this->staticRoutesByMethod[$method][$normalizedPattern][] = $index;
                }
            }
        }

        /** @param array<string|int, mixed> $params */
        public function url(string $name, array $params = []): string {
            if (!isset($this->namedRoutes[$name])) {
                throw new \RuntimeException('Route not found: ' . $name);
            }

            $route = $this->routes[$this->namedRoutes[$name]];
            $url = $route['pattern'];

            $usedParams = [];
            if (preg_match_all('/\{(\w+)\}/', $url, $matches) > 0) {
                foreach ($matches[1] as $placeholder) {
                    if (!array_key_exists($placeholder, $params)) {
                        throw new \RuntimeException('Missing route parameter "' . $placeholder . '" for route: ' . $name);
                    }
                    $url = str_replace('{' . $placeholder . '}', rawurlencode((string) $params[$placeholder]), $url);
                    $usedParams[$placeholder] = true;
                }
            }

            $query = [];
            foreach ($params as $key => $value) {
                if (!isset($usedParams[(string) $key])) {
                    $query[$key] = $value;
                }
            }

            if ($query !== []) {
                $queryString = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
                if ($queryString !== '') {
                    $url .= (str_contains($url, '?') ? '&' : '?') . $queryString;
                }
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
                    return $this->handleHttpException($e, $request);
                } catch (\Throwable $e) {
                    return $this->handleException($e, $request);
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

        /**
         * @return array{controller: string, action: string, params: array<string, string>, middleware: array<callable>}|null
         */
        private function matchRoute(string $method, string $path, bool $isAjax): ?array {
            $method = strtoupper($method);
            $normalizedPath = $this->normalizeStaticPath($path);

            foreach ($this->staticRoutesByMethod[$method][$normalizedPath] ?? [] as $i) {
                $route = $this->routes[$i];
                if ($route['ajax'] && !$isAjax) {
                    continue;
                }

                return [
                    'controller' => $route['controller'],
                    'action' => $route['action'],
                    'params' => [],
                    'middleware' => $route['middleware'],
                ];
            }

            foreach ($this->routesByMethod[$method] ?? [] as $i) {
                $route = $this->routes[$i];
                if (!preg_match($route['regex'], $path, $matches)) {
                    continue;
                }
                if ($route['ajax'] && !$isAjax) {
                    continue;
                }

                $params = [];
                foreach ($route['paramNames'] as $paramIndex => $name) {
                    $params[$name] = $matches[$paramIndex + 1] ?? '';
                }

                return [
                    'controller' => $route['controller'],
                    'action' => $route['action'],
                    'params' => $params,
                    'middleware' => $route['middleware'],
                ];
            }

            $allowed = [];
            foreach ($this->routesByMethod as $httpMethod => $indexes) {
                if ($httpMethod === $method) {
                    continue;
                }
                foreach ($indexes as $i) {
                    $route = $this->routes[$i];
                    if (!preg_match($route['regex'], $path)) {
                        continue;
                    }
                    if ($route['ajax'] && !$isAjax) {
                        continue;
                    }

                    $allowed[$httpMethod] = true;
                    break;
                }
            }

            if ($allowed !== []) {
                throw HttpException::methodNotAllowed(array_keys($allowed));
            }

            return null;
        }

        /** @return array{invoke_without_args: bool, arg_types: array<int, string>} */
        private function buildControllerMethodPlan(object $controller, string $method): array {
            $ref = new \ReflectionMethod($controller, $method);
            if ($ref->getNumberOfParameters() === 0) {
                return ['invoke_without_args' => true, 'arg_types' => []];
            }

            $argTypes = [];
            foreach ($ref->getParameters() as $param) {
                $type = $param->getType();
                if ($type instanceof \ReflectionNamedType) {
                    $typeName = $type->getName();
                    if ($typeName === Request::class || is_subclass_of($typeName, Request::class)) {
                        $argTypes[] = 'request';
                        continue;
                    }
                    if ($typeName === App::class || is_subclass_of($typeName, App::class)) {
                        $argTypes[] = 'app';
                        continue;
                    }
                }

                if ($param->isDefaultValueAvailable()) {
                    $argTypes[] = 'default';
                    continue;
                }
                $typeName = $type instanceof \ReflectionNamedType ? $type->getName() : (string) $type;
                throw new \LogicException(
                    sprintf('Controller %s::%s() parameter $%s has unsupported type %s. Only Request and App are injectable.',
                        get_class($controller), $method, $param->getName(), $typeName)
                );
            }

            return ['invoke_without_args' => false, 'arg_types' => $argTypes];
        }

        private function callControllerMethod(object $controller, string $method, Request $request): mixed {
            $key = get_class($controller) . '::' . $method;
            $plan = $this->methodCallPlanCache[$key] ??= $this->buildControllerMethodPlan($controller, $method);
            if ($plan['invoke_without_args']) {
                return $controller->{$method}();
            }

            $args = [];
            foreach ($plan['arg_types'] as $argType) {
                if ($argType === 'default') {
                    break;
                }
                $args[] = match ($argType) {
                    'request' => $request,
                    'app' => $this,
                    default => null,
                };
            }

            return $controller->{$method}(...$args);
        }

        private function invokeController(Request $request, string $controllerClass, string $action): Response {
            $controller = new $controllerClass();

            if (property_exists($controller, 'request')) {
                $controller->request = $request;
            }

            if (method_exists($controller, 'beforeRoute')) {
                $hook = $this->callControllerMethod($controller, 'beforeRoute', $request);
                if ($hook instanceof Response) {
                    return $hook;
                }
            }

            if (!method_exists($controller, $action)) {
                throw new \RuntimeException('Action not found: ' . $controllerClass . '::' . $action);
            }

            $result = $this->callControllerMethod($controller, $action, $request);

            if (method_exists($controller, 'afterRoute')) {
                $hook = $this->callControllerMethod($controller, 'afterRoute', $request);
                if ($hook instanceof Response) {
                    return $hook;
                }
            }

            if ($result instanceof Response) {
                return $result;
            }

            return new Response((string) ($result ?? ''));
        }

        private function handleHttpException(HttpException $e, Request $request): Response {
            if ($e->statusCode >= 300 && $e->statusCode < 400) {
                return new Response($e->getMessage(), $e->statusCode, $e->headers);
            }

            if ($this->errorPageHandler !== null) {
                $response = ($this->errorPageHandler)($e, $request, $this);
                if ($response instanceof Response) {
                    return $response;
                }
            }

            $debug = (int) $this->config('debug', 0);
            if ($request->isAjax()) {
                $body = $debug >= 3
                    ? $e->getMessage()
                    : (self::HTTP_STATUS_TEXT[$e->statusCode] ?? 'Error');
                return new Response($body, $e->statusCode, array_merge(
                    $e->headers,
                    ['Content-Type' => 'text/plain; charset=UTF-8'],
                ));
            }

            $html = $this->renderDefaultErrorPage($e);
            return new Response($html, $e->statusCode, array_merge(
                $e->headers,
                ['Content-Type' => 'text/html; charset=UTF-8'],
            ));
        }

        private function handleException(\Throwable $e, Request $request): Response {
            Log::error('Unhandled exception', [
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);
            $debug = (int) $this->config('debug', 0);
            $message = $debug >= 3
                ? $e->getMessage() . "\n" . $e->getTraceAsString()
                : '';
            return $this->handleHttpException(new HttpException(500, $message, $e), $request);
        }

        private function renderDefaultErrorPage(HttpException $e): string {
            $code = $e->statusCode;
            $status = self::HTTP_STATUS_TEXT[$code] ?? 'Error';
            $debug = (int) $this->config('debug', 0);
            $message = $e->getMessage();
            $showMessage = $debug >= 1 || in_array($code, [400, 422, 429], true);
            $msgHtml = ($showMessage && $message !== '')
                ? '<p style="color:#666;margin:1rem 0 0;">' . htmlspecialchars($message, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</p>'
                : '';

            return <<<HTML
                <!DOCTYPE html>
                <html>
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Error {$code}</title>
                <style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8f9fa;color:#212529}.e{text-align:center;max-width:480px;padding:2rem}.c{font-size:5rem;font-weight:700;color:#dee2e6;line-height:1}h1{font-size:1.5rem;margin:.5rem 0}a{color:#0d6efd}</style>
                </head>
                <body><div class="e"><div class="c">{$code}</div><h1>{$status}</h1>{$msgHtml}</div></body>
                </html>
                HTML;
        }

        /** @param array<string, string|null> $overrides */
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

        /** @return array{prefix: string, middleware: array<callable>, name_prefix: string} */
        private function currentRouteGroup(): array {
            $key = array_key_last($this->routeGroups);
            if ($key === null) {
                return ['prefix' => '', 'middleware' => [], 'name_prefix' => ''];
            }
            return $this->routeGroups[$key];
        }

        private function normalizeStaticPath(string $path): string {
            $normalized = rtrim($path, '/');
            return $normalized === '' ? '/' : $normalized;
        }

        private function joinRoutePath(string $prefix, string $path): string {
            if ($path === '') {
                $path = '/';
            }
            if (!str_starts_with($path, '/')) {
                $path = '/' . $path;
            }

            if ($prefix === '' || $prefix === '/') {
                return $path;
            }

            $normalizedPrefix = '/' . trim($prefix, '/');
            if ($path === '/') {
                return $normalizedPrefix;
            }

            return rtrim($normalizedPrefix, '/') . $path;
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
                    'message' => (string) $error['message'],
                    'file' => (string) $error['file'],
                    'line' => (int) $error['line'],
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
            $trusted = array_values(array_filter($trusted, static fn(mixed $ip): bool => is_string($ip) && $ip !== ''));
            $request = Request::fromGlobalsWithProxies($trusted);
            $response = $this->handle($request);
            $response->send();
        }
    }

    class Db {
        private \PDO $pdo;
        private readonly string $driver;

        /** @var array<int, array{sql: string, time: float}> */
        private array $log = [];
        private int $savepointLevel = 0;
        private bool $logQueries;
        private int $lastRowCount = 0;

        /** @param array<string, mixed> $config */
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
            $this->driver = (string) $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
            $this->logQueries = (bool) ($config['log_queries'] ?? false);
        }

        public function pdo(): \PDO {
            return $this->pdo;
        }

        public function driver(): string {
            return $this->driver;
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return array<int|string, mixed>|null
         */
        private function norm(array|string|null $params): ?array {
            if (is_string($params)) {
                return [$params];
            }
            return $params;
        }

        /** @param array<int|string, mixed>|string|null $params */
        private function run(string $sql, array|string|null $params): \PDOStatement {
            $t = microtime(true);
            $norm = $this->norm($params);
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($norm);
            $this->lastRowCount = $stmt->rowCount();
            if ($this->logQueries) {
                $this->log[] = ['sql' => $this->interpolate($sql, $norm), 'time' => microtime(true) - $t];
            }
            return $stmt;
        }

        /** @param array<int|string, mixed>|null $params */
        private function interpolate(string $sql, ?array $params): string {
            if ($params === null || $params === []) {
                return $sql;
            }
            $i = 0;
            $replaced = preg_replace_callback('/\?/', function () use ($params, &$i): string {
                $v = $params[$i++] ?? null;
                if ($v === null) {
                    return 'NULL';
                }
                if (is_int($v) || is_float($v)) {
                    return (string) $v;
                }
                return "'" . addslashes((string) $v) . "'";
            }, $sql);
            return $replaced ?? $sql;
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

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return int|list<array<string, mixed>>
         */
        public function exec(string $sql, array|string|null $params = null): int|array {
            $stmt = $this->run($sql, $params);
            if ($this->isSelectQuery($sql)) {
                $rows = $stmt->fetchAll();
                $this->lastRowCount = count($rows);
                return array_values($rows);
            }
            return $stmt->rowCount();
        }

        /** @param array<int|string, mixed>|string|null $params */
        public function var(string $sql, array|string|null $params = null): mixed {
            $row = $this->run($sql, $params)->fetch(\PDO::FETCH_NUM);
            return $row ? $row[0] : null;
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return array<string, mixed>|null
         */
        public function row(string $sql, array|string|null $params = null): ?array {
            $row = $this->run($sql, $params)->fetch();
            return $row ?: null;
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return list<array<string, mixed>>
         */
        public function results(string $sql, array|string|null $params = null): array {
            return array_values($this->run($sql, $params)->fetchAll());
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return list<mixed>
         */
        public function col(string $sql, array|string|null $params = null): array {
            return array_values($this->run($sql, $params)->fetchAll(\PDO::FETCH_COLUMN));
        }

        /** @param array<int|string, mixed>|string|null $params */
        public function insertGetId(string $sql, array|string|null $params = null): int {
            $this->run($sql, $params);
            return (int) $this->pdo->lastInsertId();
        }

        public function lastInsertId(?string $name = null): string|false {
            return $this->pdo->lastInsertId($name);
        }

        /**
         * @param array<int, string> $columns
         * @param array<int, array<int, mixed>> $rows
         */
        public function batchInsert(string $table, array $columns, array $rows, string $mode = 'INSERT'): void {
            if ($rows === [] || $columns === []) {
                return;
            }

            $allowedModes = ['INSERT', 'REPLACE', 'INSERT OR REPLACE', 'INSERT OR IGNORE', 'INSERT IGNORE'];
            $mode = strtoupper($mode);
            if (!in_array($mode, $allowedModes, true)) {
                throw new \InvalidArgumentException('Invalid insert mode: ' . $mode);
            }

            $quoteIdentifier = static fn(string $identifier): string => '`' . str_replace('`', '``', $identifier) . '`';
            $colCount = count($columns);
            $colList = implode(', ', array_map($quoteIdentifier, $columns));
            $quotedTable = $quoteIdentifier($table);
            $rowPlaceholder = '(' . implode(',', array_fill(0, $colCount, '?')) . ')';
            $maxParams = $this->driver === 'sqlite' ? 999 : 65535;
            $chunkSize = max(1, (int) floor($maxParams / $colCount));

            foreach (array_chunk($rows, $chunkSize) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), $rowPlaceholder));
                $params = [];
                foreach ($chunk as $row) {
                    foreach ($row as $value) {
                        $params[] = $value;
                    }
                }
                $this->exec("$mode INTO $quotedTable ($colList) VALUES $placeholders", $params);
            }
        }

        public function begin(): bool {
            if ($this->pdo->inTransaction()) {
                $this->savepointLevel++;
                $this->pdo->exec("SAVEPOINT sp_{$this->savepointLevel}");
                return true;
            }

            $this->savepointLevel = 0;
            return $this->pdo->beginTransaction();
        }

        public function commit(): bool {
            if ($this->savepointLevel > 0) {
                $this->pdo->exec("RELEASE SAVEPOINT sp_{$this->savepointLevel}");
                $this->savepointLevel--;
                return true;
            }

            return $this->pdo->commit();
        }

        public function rollback(): bool {
            if ($this->savepointLevel > 0) {
                $this->pdo->exec("ROLLBACK TO SAVEPOINT sp_{$this->savepointLevel}");
                $this->savepointLevel--;
                return true;
            }

            return $this->pdo->rollBack();
        }

        public function rollbackAll(): bool {
            if (!$this->pdo->inTransaction()) {
                $this->savepointLevel = 0;
                return false;
            }

            $this->savepointLevel = 0;
            return $this->pdo->rollBack();
        }

        public function trans(): bool {
            return $this->pdo->inTransaction();
        }

        public function count(): int {
            return $this->lastRowCount;
        }

        /** @param array<int, mixed> $items */
        public function placeholders(array $items): string {
            return implode(', ', array_fill(0, count($items), '?'));
        }

        public function log(): string {
            if ($this->log === []) {
                return '';
            }
            $lines = [];
            foreach ($this->log as $entry) {
                $lines[] = sprintf('(%.2fms) %s', $entry['time'] * 1000, $entry['sql']);
            }
            return implode("\n", $lines);
        }

        public function resetRequestState(): void {
            $this->log = [];
            $this->lastRowCount = 0;
            $this->savepointLevel = 0;
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
        private readonly string $realBasePath;

        /** @var array<string, mixed> */
        private array $layoutData = [];

        /** @var list<array{template: string, ms: float}> */
        private array $renderLog = [];

        public function __construct(private readonly string $basePath) {
            $resolved = realpath($basePath);
            if ($resolved === false) {
                throw new \RuntimeException('View base path not found: ' . $basePath);
            }
            $this->realBasePath = $resolved;
        }

        /** @return list<array{template: string, ms: float}> */
        public function renderLog(): array {
            return $this->renderLog;
        }

        public function renderTime(): float {
            return array_sum(array_column($this->renderLog, 'ms'));
        }

        /** @param array<string, mixed> $data */
        public function render(string $template, array $data = []): string {
            $this->layoutFile = null;
            $this->layoutData = [];

            $content = $this->renderFile($template, $data);
            $layoutFile = $this->layoutFile;
            /** @phpstan-ignore-next-line dynamic include can call View::layout() */
            if ($layoutFile !== null) {
                $layoutData = array_merge($data, $this->layoutData, ['content' => $content]);
                $this->layoutFile = null;
                $content = $this->renderFile($layoutFile, $layoutData);
            }
            return $content;
        }

        /** @param array<string, mixed> $data */
        public function layout(string $file, array $data = []): void {
            $this->layoutFile = $file;
            $this->layoutData = $data;
        }

        /** @param array<string, mixed> $data */
        public function partial(string $template, array $data = []): string {
            return $this->renderFile($template, $data);
        }

        /** @param array<string, mixed> $data */
        private function renderFile(string $template, array $data): string {
            $filePath = rtrim($this->basePath, '/') . '/' . ltrim($template, '/');
            $realBase = $this->realBasePath;
            $realFile = realpath($filePath);
            if ($realFile === false || !str_starts_with($realFile, $realBase . '/')) {
                throw new \RuntimeException('Template not found: ' . $template);
            }

            $view = $this;
            extract($data, EXTR_SKIP);

            $t = microtime(true);
            ob_start();
            try {
                include $realFile;
            } catch (\Throwable $e) {
                ob_end_clean();
                throw $e;
            }
            $result = (string) ob_get_clean();
            $this->renderLog[] = ['template' => $template, 'ms' => round((microtime(true) - $t) * 1000, 2)];
            return $result;
        }
    }

    class Session implements \SessionHandlerInterface {
        public const INTENDED_URL_KEY = '_intended_url';

        private ?string $lockName = null;
        private bool $lockAcquired = false;
        private readonly bool $useAdvisoryLock;
        private string $initialData = '';
        private bool $initialDataLoaded = false;

        public function __construct(
            private readonly Db $db,
            private readonly bool $advisory = true,
            private readonly int $lockTimeout = 30,
        ) {
            $this->useAdvisoryLock = $this->advisory && $this->db->driver() === 'mysql';
            $this->lockAcquired = !$this->useAdvisoryLock;
        }

        /** @param array<string, mixed> $cookieParams */
        public function register(array $cookieParams = []): void {
            session_set_save_handler($this, true);
            $defaults = [
                'lifetime' => 7200,
                'path' => '/',
                'domain' => '',
                'secure' => true,
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
            $this->initialData = '';
            $this->initialDataLoaded = false;
            return true;
        }

        public function read(string $id): string|false {
            if ($this->useAdvisoryLock) {
                $this->acquireLock($id);
            }

            try {
                $data = $this->db->var('SELECT data FROM sessions WHERE session_id = ?', [$id]);
                $result = is_string($data) ? $data : '';
                $this->initialData = $result;
                $this->initialDataLoaded = true;
                return $result;
            } catch (\Throwable $e) {
                $this->releaseLock();
                throw $e;
            }
        }

        public function write(string $id, string $data): bool {
            if (!$this->lockAcquired) {
                error_log('[SESSION] Refused write without advisory lock for ' . $id);
                return false;
            }

            try {
                if ($this->initialDataLoaded && $data === $this->initialData) {
                    $this->db->exec('UPDATE sessions SET stamp = ? WHERE session_id = ?', [time(), $id]);
                    return true;
                }

                $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
                $agent = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 5000);
                $stamp = time();

                $driver = $this->db->driver();
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
                $this->initialData = $data;
                $this->initialDataLoaded = true;
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
            $this->initialData = '';
            $this->initialDataLoaded = false;
            $this->releaseLock();
            return true;
        }

        public function gc(int $max_lifetime): int|false {
            $result = $this->db->exec('DELETE FROM sessions WHERE stamp < ?', [time() - $max_lifetime]);
            return is_int($result) ? $result : false;
        }

        public static function pullIntendedUrl(string $default = '/'): string {
            $url = $_SESSION[self::INTENDED_URL_KEY] ?? null;
            unset($_SESSION[self::INTENDED_URL_KEY]);

            if (!is_string($url) || $url === '' || !str_starts_with($url, '/') || str_starts_with($url, '//')) {
                return $default;
            }

            return $url;
        }

        private function acquireLock(string $id): void {
            if (!$this->useAdvisoryLock) {
                $this->lockAcquired = true;
                return;
            }

            $this->lockName = 'sess_' . substr($id, 0, 32);
            $this->lockAcquired = false;

            try {
                if ($this->db->pdo()->inTransaction()) {
                    $this->db->pdo()->rollBack();
                }

                $timeout = max(0, $this->lockTimeout);
                $result = $this->db->var('SELECT GET_LOCK(?, ?)', [$this->lockName, $timeout]);
                if ((int) $result === 1) {
                    $this->lockAcquired = true;
                    return;
                }

                error_log('[SESSION] Advisory lock timeout for ' . $this->lockName);
                $this->lockName = null;
            } catch (\Throwable $e) {
                error_log('[SESSION] Advisory lock error: ' . $e->getMessage());
                $this->lockName = null;
            }
        }

        private function releaseLock(): void {
            if ($this->lockName === null) {
                $this->lockAcquired = !$this->useAdvisoryLock;
                return;
            }

            try {
                $this->db->var('SELECT RELEASE_LOCK(?)', [$this->lockName]);
            } catch (\Throwable) {
                // Ignore release errors for non-MySQL drivers.
            }

            $this->lockName = null;
            $this->lockAcquired = !$this->useAdvisoryLock;
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

        /** @return list<array{type: string, text: string}> */
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

    class Middleware {
        /** @return callable(Request, callable): Response */
        public static function auth(string $loginRoute = 'login', string $message = 'Musisz się zalogować.'): callable {
            return function (Request $req, callable $next) use ($loginRoute, $message): Response {
                if (!isset($_SESSION['user'])) {
                    if (in_array($req->method, ['GET', 'HEAD'], true)) {
                        $queryString = http_build_query($req->query, '', '&', PHP_QUERY_RFC3986);
                        $_SESSION[Session::INTENDED_URL_KEY] = $req->path . ($queryString !== '' ? '?' . $queryString : '');
                    }

                    (new Flash())->warning($message);
                    try {
                        return Response::redirect(App::instance()->url($loginRoute));
                    } catch (\Throwable) {
                        return Response::redirect('/login');
                    }
                }

                return $next($req);
            };
        }

        /**
         * @param list<string> $methods
         * @return callable(Request, callable): Response
         */
        public static function csrf(array $methods = ['POST', 'PUT', 'PATCH', 'DELETE'], string $message = 'Sesja wygasła. Odśwież stronę.'): callable {
            $allowedMethods = array_values(array_unique(array_map(static fn($method) => strtoupper((string) $method), $methods)));

            return function (Request $req, callable $next) use ($allowedMethods, $message): Response {
                if (in_array($req->method, $allowedMethods, true)) {
                    $token = $req->post(Csrf::FIELD_NAME) ?? $req->header('X-Csrf-Token');
                    if (!Csrf::validate(is_scalar($token) ? (string) $token : null)) {
                        throw HttpException::forbidden($message);
                    }
                }

                return $next($req);
            };
        }
    }

    abstract class Controller {
        public Request $request;
        /** @var array<string, mixed> */
        protected array $data = [];

        protected function set(string $key, mixed $value): static {
            $this->data[$key] = $value;
            return $this;
        }

        protected function get(string $key, mixed $default = null): mixed {
            return $this->data[$key] ?? $default;
        }

        /** @param array<string, mixed> $data */
        protected function render(string $template, array $data = []): Response {
            $app = App::instance();
            $viewPath = (string) $app->config('view_path', 'templates');
            $view = new View($viewPath);
            $app->setLastView($view);

            $merged = array_merge($this->data, $data);
            $merged['flash'] = (new Flash())->get();
            $merged['csrf_token'] = Csrf::token();
            $merged['csrf_input'] = Csrf::hiddenInput();
            $merged['url'] = static fn(string $name, array $params = []): string => $app->url($name, $params);

            return Response::html($view->render($template, $merged));
        }

        protected function json(mixed $data, int $status = 200): Response {
            return Response::json($data, $status);
        }

        /** @param array<string, mixed> $data */
        protected function jsonSuccess(array $data = []): Response {
            return Response::json(array_merge(['success' => true], $data));
        }

        /** @param array<string, mixed> $extra */
        protected function jsonError(string $message, int $status = 400, array $extra = []): Response {
            return Response::json(array_merge(['success' => false, 'message' => $message], $extra), $status);
        }

        protected function flash(string $type, string $message): void {
            (new Flash())->add($type, $message);
        }

        protected function redirect(string $url, int $status = 302): Response {
            return Response::redirect($url, $status);
        }

        /** @param array<string|int, mixed> $params */
        protected function redirectRoute(string $name, array $params = [], int $status = 302): Response {
            return $this->redirect(App::instance()->url($name, $params), $status);
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

        /** @return array<string, mixed>|null */
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
            $raw = $this->request->post(Csrf::FIELD_NAME) ?? $this->request->header('X-Csrf-Token');
            $token = is_scalar($raw) ? (string) $raw : null;
            if (!Csrf::validate($token)) {
                throw HttpException::forbidden('Sesja wygasła. Odśwież stronę.');
            }
        }

        protected function param(string $key, mixed $default = null): mixed {
            return $this->request->param($key, $default);
        }

        /**
         * Extract request data (POST body + query string) for the given keys.
         *
         * @param list<string> $keys
         * @return array<string, mixed>
         */
        protected function postData(array $keys): array {
            return $this->request->only($keys);
        }

        /** @return array{page: int, offset: int, total_pages: int, per_page: int, total: int} */
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

        /** @param array<string, mixed> $ctx */
        public static function trace(string $msg, array $ctx = []): void {
            self::log('trace', $msg, $ctx);
        }

        /** @param array<string, mixed> $ctx */
        public static function debug(string $msg, array $ctx = []): void {
            self::log('debug', $msg, $ctx);
        }

        /** @param array<string, mixed> $ctx */
        public static function info(string $msg, array $ctx = []): void {
            self::log('info', $msg, $ctx);
        }

        /** @param array<string, mixed> $ctx */
        public static function warn(string $msg, array $ctx = []): void {
            self::log('warn', $msg, $ctx);
        }

        /** @param array<string, mixed> $ctx */
        public static function error(string $msg, array $ctx = []): void {
            self::log('error', $msg, $ctx);
        }

        public static function toFile(string $filename, string $message): void {
            if (self::$basePath === null) {
                return;
            }
            if (str_contains($filename, '/') || str_contains($filename, '\\') || str_contains($filename, "\0")) {
                throw new \InvalidArgumentException('Invalid log filename: ' . $filename);
            }

            if (!is_dir(self::$basePath)) {
                @mkdir(self::$basePath, 0755, true);
            }

            $path = self::$basePath . '/' . date('Y') . '_' . $filename;
            @file_put_contents($path, date('[Y-m-d H:i:s] ') . $message . "\n", FILE_APPEND | LOCK_EX);
        }

        /** @param array<string, mixed> $ctx */
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

        /**
         * @param array<string, string|list<string>> $rules
         * @param array<string, mixed> $data
         * @return array<string, string>
         */
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
        private readonly bool $hasApcu;
        private readonly string $apcuPrefix;
        private readonly ?string $dir;

        public function __construct(?string $dir = null) {
            $this->hasApcu = function_exists('apcu_enabled') && apcu_enabled();
            if (!$this->hasApcu && $dir === null) {
                throw new \RuntimeException('Cache directory is required when APCu is unavailable.');
            }

            if ($dir !== null && !is_dir($dir)) {
                throw new \RuntimeException('Cache directory does not exist: ' . $dir);
            }

            $this->dir = $dir;
            $this->apcuPrefix = 'pframe:cache:' . md5($dir ?? '__no_dir__') . ':';
        }

        public function get(string $key, mixed $default = null): mixed {
            if ($this->hasApcu) {
                $success = false;
                $value = apcu_fetch($this->apcuKey($key), $success);
                return $success ? $value : $default;
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
            if ($this->hasApcu) {
                apcu_store($this->apcuKey($key), $value, max(0, $ttl));
                return;
            }

            file_put_contents(
                $this->path($key),
                serialize(['value' => $value, 'ttl' => $ttl, 'time' => time()]),
                LOCK_EX,
            );
        }

        public function delete(string $key): void {
            if ($this->hasApcu) {
                apcu_delete($this->apcuKey($key));
                return;
            }

            $path = $this->path($key);
            if (is_file($path)) {
                unlink($path);
            }
        }

        public function clear(): void {
            if ($this->hasApcu) {
                $this->clearApcu();
            }

            if ($this->dir === null) {
                return;
            }

            foreach (glob($this->dir . '/*.cache') ?: [] as $file) {
                unlink($file);
            }
            foreach (glob($this->dir . '/*.lock') ?: [] as $file) {
                unlink($file);
            }
        }

        public function rateCheck(string $scope, string $id, int $max, int $window): ?int {
            $key = 'rl:' . $scope . ':' . $id;
            return $this->withRateLock($key, function () use ($key, $max, $window): ?int {
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
            });
        }

        private function path(string $key): string {
            return $this->requireDir() . '/' . md5($key) . '.cache';
        }

        private function apcuKey(string $key): string {
            return $this->apcuPrefix . md5($key);
        }

        private function clearApcu(): void {
            if (!function_exists('apcu_cache_info')) {
                return;
            }

            $cacheInfo = apcu_cache_info(false);
            if (!is_array($cacheInfo)) {
                return;
            }

            $cacheList = $cacheInfo['cache_list'] ?? null;
            if (!is_array($cacheList)) {
                return;
            }

            foreach ($cacheList as $entry) {
                $entryKey = is_array($entry) ? ($entry['info'] ?? null) : null;
                if (is_string($entryKey) && str_starts_with($entryKey, $this->apcuPrefix)) {
                    apcu_delete($entryKey);
                }
            }
        }

        private function requireDir(): string {
            if ($this->dir === null) {
                throw new \RuntimeException('Cache directory is required for file backend.');
            }
            return $this->dir;
        }

        private function withRateLock(string $key, callable $callback): ?int {
            if ($this->dir === null) {
                if (!$this->hasApcu || !function_exists('apcu_add')) {
                    return 1;
                }

                $lockKey = $this->apcuPrefix . 'lock:' . md5($key);
                if (!apcu_add($lockKey, 1, 1)) {
                    return 1;
                }

                try {
                    return $callback();
                } finally {
                    apcu_delete($lockKey);
                }
            }

            $lockPath = $this->dir . '/' . md5($key) . '.lock';
            $handle = @fopen($lockPath, 'c');
            if ($handle === false) {
                return 1;
            }

            try {
                if (!@flock($handle, LOCK_EX)) {
                    return 1;
                }

                try {
                    return $callback();
                } finally {
                    @flock($handle, LOCK_UN);
                }
            } finally {
                fclose($handle);
            }
        }
    }

    class TickTask {
        private int $interval = 60;
        private ?string $windowFrom = null;
        private ?string $windowTo = null;
        private int $maxRetries = 3;
        /** @var ?\Closure */
        private ?\Closure $callback = null;
        private ?string $cmd = null;
        private int $cmdTimeout = 60;

        public function __construct(
            public readonly string $name,
        ) {}

        public function every(int $seconds): self {
            $this->interval = $seconds;
            return $this;
        }

        public function between(string $from, string $to): self {
            $this->windowFrom = $from;
            $this->windowTo = $to;
            return $this;
        }

        public function retries(int $max): self {
            $this->maxRetries = max(0, $max);
            return $this;
        }

        /** @param callable $callback */
        public function run(callable $callback): self {
            $this->callback = $callback(...);
            return $this;
        }

        /**
         * Run a shell command as the task action.
         *
         * WARNING: The command string is passed directly to the shell via proc_open().
         * Never build commands from untrusted input without proper escaping
         * (escapeshellarg()/escapeshellcmd()). The caller is responsible for safety.
         */
        public function command(string $cmd, int $timeout = 60): self {
            $this->cmd = $cmd;
            $this->cmdTimeout = $timeout;
            return $this;
        }

        public function getInterval(): int {
            return $this->interval;
        }

        public function getMaxRetries(): int {
            return $this->maxRetries;
        }

        public function inTimeWindow(?string $now = null): bool {
            if ($this->windowFrom === null || $this->windowTo === null) {
                return true;
            }

            $timeNow = $now ?? date('H:i');
            if ($this->windowFrom <= $this->windowTo) {
                return $timeNow >= $this->windowFrom && $timeNow < $this->windowTo;
            }

            return $timeNow >= $this->windowFrom || $timeNow < $this->windowTo;
        }

        /** @return array{success: bool, error?: string, output?: string} */
        public function execute(): array {
            try {
                if ($this->cmd !== null) {
                    return $this->executeCommand();
                }
                if ($this->callback !== null) {
                    ($this->callback)();
                    return ['success' => true];
                }
                return ['success' => false, 'error' => 'No callback or command configured'];
            } catch (\Throwable $e) {
                return ['success' => false, 'error' => $e->getMessage()];
            }
        }

        /** @return array{success: bool, error?: string, output?: string} */
        private function executeCommand(): array {
            $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $command = $this->cmd;
            if ($command === null) {
                return ['success' => false, 'error' => 'No command configured'];
            }

            $process = proc_open($command, $descriptors, $pipes);
            if (!is_resource($process)) {
                return ['success' => false, 'error' => 'Failed to start process'];
            }

            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);

            $deadline = time() + $this->cmdTimeout;
            $stdout = '';
            $stderr = '';

            while (true) {
                $status = proc_get_status($process);
                if (!$status['running']) {
                    break;
                }
                if (time() >= $deadline) {
                    // Kill process GROUP (negative PID) to include children
                    $pid = $status['pid'];
                    if (function_exists('posix_kill')) {
                        @posix_kill(-$pid, 9);
                    }
                    @proc_terminate($process, 9);
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    proc_close($process);
                    return ['success' => false, 'error' => "Timeout after {$this->cmdTimeout}s"];
                }
                $stdout .= stream_get_contents($pipes[1]) ?: '';
                $stderr .= stream_get_contents($pipes[2]) ?: '';
                usleep(50_000); // 50ms poll
            }

            $stdout .= stream_get_contents($pipes[1]) ?: '';
            $stderr .= stream_get_contents($pipes[2]) ?: '';
            fclose($pipes[1]);
            fclose($pipes[2]);

            $exitCode = proc_close($process);

            if ($exitCode !== 0) {
                return ['success' => false, 'error' => "Exit code {$exitCode}: " . trim($stderr ?: $stdout)];
            }
            return ['success' => true, 'output' => trim($stdout)];
        }
    }

    class Tick {
        /** @var array<string, TickTask> */
        private array $tasks = [];
        private bool $hasApcu;
        private string $tickDir;
        private string $keyPrefix;

        public function __construct(
            private readonly string $cacheDir,
            private readonly int $throttleSeconds = 30,
            string $prefix = '',
        ) {
            $this->hasApcu = function_exists('apcu_enabled') && apcu_enabled();
            $this->tickDir = $this->cacheDir . '/tick';
            $this->keyPrefix = 'tick:' . ($prefix !== '' ? $prefix : md5($cacheDir)) . ':';
            if (!is_dir($this->tickDir)) {
                @mkdir($this->tickDir, 0755, true);
            }
        }

        public function task(string $name): TickTask {
            $task = new TickTask($name);
            $this->tasks[$name] = $task;
            return $task;
        }

        /**
         * Evaluate and run due tasks.
         * @return array<string, array{success: bool, error?: string}>
         */
        public function dispatch(bool $forceRun = false): array {
            if (!$forceRun && !$this->globalThrottlePass()) {
                return [];
            }

            $results = [];
            foreach ($this->tasks as $name => $task) {
                if (!$this->isDue($task) || !$this->tryLock($name)) {
                    continue;
                }

                try {
                    $results[$name] = $task->execute();
                    if ($results[$name]['success']) {
                        $this->setLastRun($name, time());
                        $this->resetFailCount($name);
                        continue;
                    }

                    $failures = $this->incrementFailCount($name);
                    if ($failures >= $task->getMaxRetries()) {
                        $this->setLastRun($name, time());
                        $this->resetFailCount($name);
                    }
                } finally {
                    $this->unlock($name);
                }
            }
            return $results;
        }

        private function globalThrottlePass(): bool {
            if ($this->throttleSeconds <= 0) {
                return true;
            }

            $key = $this->keyPrefix . 'global';
            if ($this->hasApcu) {
                return apcu_add($key, 1, $this->throttleSeconds);
            }
            // File fallback: flock + persisted timestamp for atomic throttle.
            $path = $this->tickDir . '/' . md5($key) . '.tick';
            $handle = @fopen($path, 'c+');
            if ($handle === false) {
                return true; // fail-open: run if can't check
            }
            if (!flock($handle, LOCK_EX | LOCK_NB)) {
                fclose($handle);
                return false;
            }
            rewind($handle);
            $content = stream_get_contents($handle);
            $lastThrottle = $content === false || trim($content) === '' ? null : (int)trim($content);
            if ($lastThrottle !== null && (time() - $lastThrottle) < $this->throttleSeconds) {
                flock($handle, LOCK_UN);
                fclose($handle);
                return false;
            }

            // Store current throttle timestamp while holding lock.
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, (string)time());
            fflush($handle);
            flock($handle, LOCK_UN);
            fclose($handle);
            return true;
        }

        private function isDue(TickTask $task): bool {
            if (!$task->inTimeWindow()) {
                return false;
            }
            $lastRun = $this->getLastRun($task->name);
            if ($lastRun === null) {
                return true;
            }
            return (time() - $lastRun) >= $task->getInterval();
        }

        private function getLastRun(string $name): ?int {
            $key = $this->keyPrefix . $name . ':last';
            if ($this->hasApcu) {
                $val = apcu_fetch($key, $success);
                return $success ? (int)$val : null;
            }
            $path = $this->tickDir . '/' . md5($key) . '.last';
            if (!is_file($path)) {
                return null;
            }
            $content = @file_get_contents($path);
            return $content !== false ? (int)$content : null;
        }

        private function setLastRun(string $name, int $timestamp): void {
            $key = $this->keyPrefix . $name . ':last';
            if ($this->hasApcu) {
                apcu_store($key, $timestamp, 0);
            }
            // Always write file (persistent across APCu clears/restarts)
            $path = $this->tickDir . '/' . md5($key) . '.last';
            @file_put_contents($path, (string)$timestamp, LOCK_EX);
        }

        private function getFailCount(string $name): int {
            $path = $this->tickDir . '/' . md5($this->keyPrefix . $name . ':fail') . '.fail';
            if (!is_file($path)) {
                return 0;
            }
            $content = @file_get_contents($path);
            if ($content === false) {
                return 0;
            }
            return max(0, (int)$content);
        }

        private function incrementFailCount(string $name): int {
            $path = $this->tickDir . '/' . md5($this->keyPrefix . $name . ':fail') . '.fail';
            $handle = @fopen($path, 'c+');
            if ($handle === false) {
                $count = $this->getFailCount($name) + 1;
                @file_put_contents($path, (string)$count, LOCK_EX);
                return $count;
            }

            try {
                if (!flock($handle, LOCK_EX)) {
                    $count = $this->getFailCount($name) + 1;
                    @file_put_contents($path, (string)$count, LOCK_EX);
                    return $count;
                }

                rewind($handle);
                $content = stream_get_contents($handle);
                $count = max(0, (int)($content ?: '0')) + 1;
                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, (string)$count);
                fflush($handle);
                flock($handle, LOCK_UN);
                return $count;
            } finally {
                fclose($handle);
            }
        }

        private function resetFailCount(string $name): void {
            @unlink($this->tickDir . '/' . md5($this->keyPrefix . $name . ':fail') . '.fail');
        }

        /** @var array<string, resource> File lock handles (kept open until unlock) */
        private array $lockHandles = [];

        private function tryLock(string $name): bool {
            // File lock — flock is atomic and race-safe.
            $path = $this->tickDir . '/' . md5($this->keyPrefix . $name . ':lock') . '.lock';
            $handle = @fopen($path, 'c');
            if ($handle === false) {
                return false;
            }
            if (!flock($handle, LOCK_EX | LOCK_NB)) {
                fclose($handle);
                return false;
            }
            $this->lockHandles[$name] = $handle;
            return true;
        }

        private function unlock(string $name): void {
            if (isset($this->lockHandles[$name])) {
                flock($this->lockHandles[$name], LOCK_UN);
                fclose($this->lockHandles[$name]);
                unset($this->lockHandles[$name]);
            }
            @unlink($this->tickDir . '/' . md5($this->keyPrefix . $name . ':lock') . '.lock');
        }
    }

    class DebugBar {
        public function __construct(
            private App $app,
        ) {}

        /**
         * @param list<array<string, mixed>> $rows
         * @param callable(array<string, mixed>, int): array{prefix: string, sql: string} $formatter
         * @return array{short: string, full: string}
         */
        private function buildSqlViews(array $rows, int $shortLimit, callable $formatter): array {
            $shortRows = '';
            $fullRows = '';
            foreach ($rows as $i => $row) {
                $line = $formatter($row, $i);
                $sql = (string) preg_replace('/\s+/', ' ', trim($line['sql']));
                $shortSql = mb_strlen($sql) > $shortLimit ? mb_substr($sql, 0, $shortLimit) . '…' : $sql;
                $prefix = $line['prefix'] === '' ? '' : $line['prefix'] . ' ';
                $shortRows .= '<div>' . $prefix . h($shortSql) . '</div>';
                $fullRows .= '<div>' . $prefix . h($sql) . '</div>';
            }

            return ['short' => $shortRows, 'full' => $fullRows];
        }

        private function renderSqlToggleSection(
            string $id,
            string $suffix,
            string $shortRows,
            string $fullRows,
            string $shortStyle,
            string $fullStyle,
            bool $compact = true,
        ): string {
            $shortDisplay = $compact ? 'block' : 'none';
            $fullDisplay = $compact ? 'none' : 'block';

            return '<pre style="' . $shortStyle . ';display:' . $shortDisplay . '" id="' . $id . '-' . $suffix . '-short">'
                . $shortRows
                . '</pre><pre style="' . $fullStyle . ';display:' . $fullDisplay . '" id="' . $id . '-' . $suffix . '-full">'
                . $fullRows
                . '</pre>';
        }

        /**
         * @param array{included_files: list<string>, views: list<array{template: string, ms: float}>} $d
         * @return array{list: string, count: int}
         */
        private function renderFilesList(array $d): array {
            $files = $d['included_files'];
            $viewTimes = [];
            foreach ($d['views'] as $v) {
                $viewTimes[$v['template']] = $v['ms'];
            }

            $viewFiles = [];
            $otherFiles = [];
            foreach ($files as $f) {
                $matched = false;
                foreach ($viewTimes as $tpl => $ms) {
                    if (str_ends_with($f, '/' . ltrim($tpl, '/'))) {
                        $viewFiles[] = ['path' => $f, 'ms' => $ms];
                        $matched = true;
                        break;
                    }
                }
                if (!$matched) {
                    $otherFiles[] = $f;
                }
            }

            usort($viewFiles, static fn(array $a, array $b): int => $b['ms'] <=> $a['ms']);
            $list = '';
            foreach ($viewFiles as $vf) {
                $list .= '<div><b style="color:#986801">(' . $vf['ms'] . 'ms)</b> ' . h($vf['path']) . '</div>';
            }
            foreach ($otherFiles as $f) {
                $list .= '<div>' . h($f) . '</div>';
            }

            return ['list' => $list, 'count' => count($files)];
        }

        /** @param array{gen_ms: float, db_ms: float, db_count: int, view_ms: float, views: list<array{template: string, ms: float}>, mem_mb: float, peak_mb: float} $d */
        private function renderSummary(array $d, string $id, int $fileCount): string {
            return 'Gen: <b>' . $d['gen_ms'] . 'ms</b>'
                . ' | DB: <b>' . $d['db_ms'] . 'ms</b> (' . $d['db_count'] . ')'
                . ' | View: <b>' . $d['view_ms'] . 'ms</b> (' . count($d['views']) . ')'
                . ' | Mem: <b>' . $d['mem_mb'] . 'MB</b> (peak: ' . $d['peak_mb'] . 'MB)'
                . ' | <span style="cursor:pointer;text-decoration:underline" id="' . $id . '-files-toggle">Files: <b>' . $fileCount . '</b></span>'
                . ' | <span style="cursor:pointer;text-decoration:underline" id="' . $id . '-toggle">toggle</span>';
        }

        /** @param array{db_count: int, slowest: list<array{sql: string, ms: float}>, duplicates: list<array{pattern: string|null, count: int, total_ms: float}>} $d */
        private function renderInsightsBox(array $d, string $id): string {
            $slowSection = '';
            if ($d['db_count'] >= 10 && $d['slowest'] !== []) {
                $slowViews = $this->buildSqlViews(
                    $d['slowest'],
                    100,
                    static fn(array $s, int $_): array => [
                        'prefix' => '<b>' . $s['ms'] . 'ms</b>',
                        'sql' => (string) $s['sql'],
                    ],
                );
                $slowSection = '<div><b>Top slow:</b></div>'
                    . $this->renderSqlToggleSection(
                        $id,
                        'slow',
                        $slowViews['short'],
                        $slowViews['full'],
                        'margin:0;font:inherit;white-space:pre;overflow-x:auto',
                        'margin:0;font:inherit;white-space:pre;overflow-x:auto',
                    );
            }

            $dupsSection = '';
            if ($d['duplicates'] !== []) {
                $dupsViews = $this->buildSqlViews(
                    $d['duplicates'],
                    90,
                    static fn(array $dup, int $_): array => [
                        'prefix' => '<b>' . $dup['count'] . '×</b> (' . $dup['total_ms'] . 'ms)',
                        'sql' => (string) ($dup['pattern'] ?? ''),
                    ],
                );
                $dupsSection = '<div style="margin-top:4px"><b>N+1 candidates:</b></div>'
                    . $this->renderSqlToggleSection(
                        $id,
                        'dups',
                        $dupsViews['short'],
                        $dupsViews['full'],
                        'margin:0;font:inherit;white-space:pre;overflow-x:auto',
                        'margin:0;font:inherit;white-space:pre;overflow-x:auto',
                    );
            }

            if ($slowSection === '' && $dupsSection === '') {
                return '';
            }

            return '<div style="background:#f5f5f0;border:1px solid #ddd;padding:6px 10px;margin-top:8px;border-radius:3px" id="' . $id . '-insights">'
                . $slowSection
                . $dupsSection
                . '</div>';
        }

        /** @return array{gen_ms: float, db_ms: float, db_count: int, view_ms: float, views: list<array{template: string, ms: float}>, mem_mb: float, peak_mb: float, included_files: list<string>, queries: list<array{sql: string, ms: float}>, duplicates: list<array{pattern: string|null, count: int, total_ms: float}>, slowest: list<array{sql: string, ms: float}>} */
        public function toArray(): array {
            $queries = [];
            $db = $this->app->dbIfInitialized();
            if ($db !== null) {
                foreach ($db->queryLog() as $entry) {
                    $queries[] = [
                        'sql' => $entry['sql'],
                        'ms' => round($entry['time'] * 1000, 2),
                    ];
                }
            }

            // Detect duplicate query patterns (N+1)
            $patterns = [];
            foreach ($queries as $q) {
                $pattern = preg_replace(['/\'[^\']*\'/', '/\b\d+\b/', '/\s+/'], ['?', '?', ' '], $q['sql']);
                $patterns[$pattern] ??= ['pattern' => $pattern, 'count' => 0, 'total_ms' => 0.0];
                $patterns[$pattern]['count']++;
                $patterns[$pattern]['total_ms'] += $q['ms'];
            }
            $duplicates = array_values(array_filter($patterns, static fn(array $p): bool => $p['count'] > 1));
            usort($duplicates, static fn(array $a, array $b): int => $b['count'] <=> $a['count']);
            foreach ($duplicates as &$dup) {
                $dup['total_ms'] = round($dup['total_ms'], 2);
            }
            unset($dup);

            // Top 3 slowest queries
            $slowest = $queries;
            usort($slowest, static fn(array $a, array $b): int => $b['ms'] <=> $a['ms']);
            $slowest = array_slice($slowest, 0, 3);

            // View render log
            $views = [];
            $view = $this->app->lastView();
            if ($view !== null) {
                $views = $view->renderLog();
            }

            return [
                'gen_ms' => round($this->app->elapsed() * 1000, 1),
                'db_ms' => round(array_sum(array_column($queries, 'ms')), 1),
                'db_count' => count($queries),
                'view_ms' => round(array_sum(array_column($views, 'ms')), 1),
                'views' => $views,
                'mem_mb' => round(memory_get_usage(true) / 1048576, 1),
                'peak_mb' => round(memory_get_peak_usage(true) / 1048576, 1),
                'included_files' => get_included_files(),
                'queries' => $queries,
                'duplicates' => $duplicates,
                'slowest' => $slowest,
            ];
        }

        public function toJson(): string {
            return json_encode($this->toArray(), JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        }

        public function render(): string {
            $d = $this->toArray();
            $id = 'pf-dbg-' . mt_rand(1000, 9999);
            $qs = $d['queries'];

            $queryViews = ['short' => '', 'full' => ''];
            if ($qs === []) {
                $queryViews['short'] = '<div>Brak zapytań.</div>';
                $queryViews['full'] = $queryViews['short'];
            } else {
                $queryViews = $this->buildSqlViews(
                    $qs,
                    120,
                    static fn(array $q, int $i): array => [
                        'prefix' => ($i + 1) . '. (' . $q['ms'] . 'ms)',
                        'sql' => (string) $q['sql'],
                    ],
                );
            }

            $files = $this->renderFilesList($d);
            $summary = $this->renderSummary($d, $id, $files['count']);
            $querySection = $this->renderSqlToggleSection(
                $id,
                'queries',
                $queryViews['short'],
                $queryViews['full'],
                'margin:0;font:inherit;white-space:pre-wrap',
                'margin:0;font:inherit;white-space:pre;overflow-x:auto',
            );
            $insightsBox = $this->renderInsightsBox($d, $id);

            return <<<HTML
            <div id="{$id}" style="background:#e8e8e8;color:#333;font-family:monospace;font-size:14px;padding:10px 14px;border-top:1px solid #ccc;margin-top:2rem;line-height:1.6">
            {$querySection}{$insightsBox}
            <div style="margin-top:6px">{$summary}</div>
            <pre style="margin:0;font:inherit;white-space:pre;overflow-x:auto;display:none;margin-top:6px;font-size:12px;color:#555" id="{$id}-files">{$files['list']}</pre>
            </div>
            <script>document.getElementById('{$id}-toggle').addEventListener('click',function(){['queries','slow','dups'].forEach(function(name){var s=document.getElementById('{$id}-'+name+'-short'),f=document.getElementById('{$id}-'+name+'-full');if(!s||!f){return}if(f.style.display==='none'){f.style.display='block';s.style.display='none'}else{f.style.display='none';s.style.display='block'}})});document.getElementById('{$id}-files-toggle').addEventListener('click',function(){var fl=document.getElementById('{$id}-files');fl.style.display=fl.style.display==='none'?'block':'none'})</script>
            HTML;
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

        /** @param array<string|int, mixed> $params */
        public static function url(string $name, array $params = []): string {
            return self::app()->url($name, $params);
        }

        /** @param array<int|string, mixed>|string|null $params */
        public static function var(string $sql, array|string|null $params = null): mixed {
            return self::db()->var($sql, $params);
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return array<string, mixed>|null
         */
        public static function row(string $sql, array|string|null $params = null): ?array {
            return self::db()->row($sql, $params);
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return list<array<string, mixed>>
         */
        public static function results(string $sql, array|string|null $params = null): array {
            return self::db()->results($sql, $params);
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return list<mixed>
         */
        public static function col(string $sql, array|string|null $params = null): array {
            return self::db()->col($sql, $params);
        }

        /**
         * @param array<int|string, mixed>|string|null $params
         * @return int|list<array<string, mixed>>
         */
        public static function exec(string $sql, array|string|null $params = null): int|array {
            return self::db()->exec($sql, $params);
        }

        /** @param array<int|string, mixed>|string|null $params */
        public static function insertGetId(string $sql, array|string|null $params = null): int {
            return self::db()->insertGetId($sql, $params);
        }

        public static function lastInsertId(?string $name = null): string|false {
            return self::db()->lastInsertId($name);
        }

        /**
         * @param array<int, string> $columns
         * @param array<int, array<int, mixed>> $rows
         */
        public static function batchInsert(string $table, array $columns, array $rows, string $mode = 'INSERT'): void {
            self::db()->batchInsert($table, $columns, $rows, $mode);
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

    /** @phpstan-ignore-next-line */
    function ha(array $array, string|int $key, mixed $default = ''): string {
        return h($array[$key] ?? $default);
    }

    /** @phpstan-ignore-next-line */
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

    /** @phpstan-ignore-next-line */
    function explodeS(string $separator, mixed $string, int $limit = PHP_INT_MAX): array {
        if ($string === null || $string === '' || $string === []) {
            return [];
        }
        if ($separator === '') {
            return [];
        }
        if (!is_scalar($string) && !$string instanceof \Stringable) {
            return [];
        }

        return array_map('trim', explode($separator, (string) $string, $limit));
    }
}
