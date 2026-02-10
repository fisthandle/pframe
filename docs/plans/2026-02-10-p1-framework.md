# P1 Framework — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Single-file PHP 8.4+ micro-framework (zero deps) extracting proven patterns from 4 F3 projects (ogloszenia, pat, prowadzacy, brat).

**Architecture:** One file `src/P1.php` (~1500 lines) containing all classes in `namespace P1` + global helpers. Usage: `require 'P1.php'` + `class_alias(P1\P1::class, 'P1')`. No Composer required for production. Composer used only for development (PHPUnit).

**Tech Stack:** PHP 8.4+, PDO/MySQL, PHPUnit 11

---

## Directory Structure

```
src/
└── P1.php              # THE framework — single file, all classes + helpers
tests/
├── Unit/               # Per-class unit tests
├── Integration/        # Full request cycle tests
├── bootstrap.php
└── fixtures/
db/
└── sessions.sql        # Session table schema
composer.json           # Dev only (phpunit)
phpunit.xml
.gitignore
```

## Single File Layout (`src/P1.php`)

```php
<?php
/**
 * P1 Framework — PHP 8.4+ micro-framework
 * Single-file, zero dependencies
 */
declare(strict_types=1);

namespace P1 {

    // --- Exceptions ---
    class HttpException { ... }

    // --- HTTP ---
    class Request { ... }
    class Response { ... }

    // --- Core ---
    class App { /* routing + config + middleware */ }
    class Controller { ... }
    class View { ... }
    class Db { ... }
    class Session { ... }

    // --- Auth / UX ---
    class Csrf { ... }
    class Flash { ... }

    // --- Utilities (optional, loaded but zero overhead if unused) ---
    class Log { ... }
    class Validator { ... }
    class Cache { ... }
    class Mail { ... }

    // --- Facade ---
    class P1 { ... }

} // end namespace P1

namespace {

    // --- Global Helpers ---
    function h() { ... }
    function ha() { ... }
    // etc.

} // end global namespace
```

## Usage in a Project

```
myproject/
├── public/index.php
├── lib/P1.php           # ← just copy this file
├── config/app.php
├── templates/
├── logs/
└── tmp/cache/
```

```php
<?php
// public/index.php
require dirname(__DIR__) . '/lib/P1.php';
class_alias(P1\P1::class, 'P1');

$app = P1::app();
$app->loadConfig(dirname(__DIR__) . '/config/app.php');

// Start DB session
$session = new P1\Session(P1::db());
$session->register();
session_start();

// Global CSRF on POST
$app->addMiddleware(function (P1\Request $req, callable $next): P1\Response {
    if ($req->isPost()) {
        $token = $req->post(P1\Csrf::FIELD_NAME) ?? $req->header('X-Csrf-Token');
        if (!P1\Csrf::validate($token)) {
            throw new P1\HttpException(403, 'Sesja wygasła.');
        }
    }
    return $next($req);
});

// Routes
$app->get('/', App\HomeController::class, 'index', name: 'home');
$app->get('/o/{slug}', App\AdController::class, 'show', name: 'ad.show');
$app->post('/o', App\AdController::class, 'create');
$app->post('/api/vote', App\VoteController::class, 'store', ajax: true);

$app->run();

// URL generation anywhere: P1::url('ad.show', ['slug' => 'test']) → '/o/test'
```

```php
<?php
// config/app.php
return [
    'debug' => 3,
    'timezone' => 'Europe/Warsaw',
    'view_path' => dirname(__DIR__) . '/templates',
    'log_path' => dirname(__DIR__) . '/logs',
    'cache_path' => dirname(__DIR__) . '/tmp/cache',
    'trusted_proxies' => ['10.0.0.1'],
    'db' => [
        'host' => 'localhost',
        'port' => 3306,
        'name' => 'myapp',
        'user' => 'root',
        'pass' => 'secret',
        'log_queries' => false,
    ],
    'smtp' => [
        'host' => 'smtp.gmail.com',
        'port' => 587,
        'user' => 'me@gmail.com',
        'pass' => 'apppass',
        'from_email' => 'me@gmail.com',
        'from_name' => 'MyApp',
    ],
];
```

## Security / Ops Additions

```php
// Security headers (CSP, HSTS for HTTPS, XFO, XCTO, Referrer, Permissions)
$app->addSecurityHeaders();

// Recommended session hardening
$session = new P1\Session(P1::db());
$session->register([
    'secure' => true,     // set true on HTTPS
    'samesite' => 'Lax',  // or 'Strict' for stricter apps
]);
session_start();

// After login
$session->regenerate();
```

Notes:
- `trusted_proxies` enables safe IP resolution from `X-Forwarded-For`.
- `db.log_queries` controls SQL logging; default is `false`.

---

## Task 1: Project Setup

**Files:**
- Create: `composer.json`
- Create: `phpunit.xml`
- Create: `tests/bootstrap.php`
- Create: `src/P1.php` (skeleton with namespace blocks)
- Create: `.gitignore`

**Step 1: Create composer.json (dev-only — PHPUnit)**

```json
{
    "name": "p1/framework",
    "description": "Single-file PHP 8.4+ micro-framework",
    "type": "library",
    "license": "MIT",
    "require": {
        "php": ">=8.4"
    },
    "require-dev": {
        "phpunit/phpunit": "^11.0"
    },
    "autoload": {
        "files": [
            "src/P1.php"
        ]
    },
    "autoload-dev": {
        "psr-4": {
            "P1\\Tests\\": "tests/"
        }
    }
}
```

**Step 2: Create phpunit.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="tests/bootstrap.php"
         colors="true"
         testdox="true">
    <testsuites>
        <testsuite name="Unit">
            <directory>tests/Unit</directory>
        </testsuite>
        <testsuite name="Integration">
            <directory>tests/Integration</directory>
        </testsuite>
    </testsuites>
</phpunit>
```

**Step 3: Create tests/bootstrap.php**

```php
<?php
declare(strict_types=1);
define('TESTING', true);
require dirname(__DIR__) . '/vendor/autoload.php';
```

**Step 4: Create src/P1.php skeleton**

```php
<?php
/**
 * P1 Framework — PHP 8.4+ micro-framework
 * Single-file, zero dependencies
 *
 * Usage: require 'P1.php'; class_alias(P1\P1::class, 'P1');
 */
declare(strict_types=1);

// ============================================================================
// P1 NAMESPACE — All framework classes
// ============================================================================
namespace P1 {

// Classes will be added here incrementally

} // end namespace P1

// ============================================================================
// GLOBAL HELPERS
// ============================================================================
namespace {

// Helper functions will be added here

} // end global namespace
```

**Step 5: Create .gitignore**

```
/vendor/
```

**Step 6: Create test directories & install dependencies**

```bash
cd ~/dev/frame && mkdir -p tests/Unit tests/Integration tests/fixtures/config
composer install
vendor/bin/phpunit
```
Expected: 0 tests, 0 assertions (clean run)

**Step 7: Commit**

```bash
git add .gitignore composer.json composer.lock phpunit.xml src/P1.php tests/bootstrap.php
git commit -m "feat: project setup — single-file framework skeleton"
```

---

## Task 2: Helpers + HttpException

**Files:**
- Modify: `src/P1.php` (add HttpException class + global helpers)
- Create: `tests/Unit/HelpersTest.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;

class HelpersTest extends TestCase
{
    public function testHEscapesHtml(): void
    {
        $this->assertSame('&lt;script&gt;', h('<script>'));
        $this->assertSame('&amp;', h('&'));
        $this->assertSame('', h(null));
        $this->assertSame('', h(''));
        $this->assertSame('hello', h('hello'));
    }

    public function testHaEscapesArrayValue(): void
    {
        $data = ['name' => '<b>Joe</b>', 'age' => 30];
        $this->assertSame('&lt;b&gt;Joe&lt;/b&gt;', ha($data, 'name'));
        $this->assertSame('30', ha($data, 'age'));
        $this->assertSame('default', ha($data, 'missing', 'default'));
        $this->assertSame('', ha($data, 'missing'));
    }

    public function testSGetReturnsValueOrDefault(): void
    {
        $data = ['key' => 'val'];
        $this->assertSame('val', sGet($data, 'key'));
        $this->assertNull(sGet($data, 'missing'));
        $this->assertSame('def', sGet($data, 'missing', 'def'));
        $this->assertNull(sGet(null, 'key'));
    }

    public function testMlen(): void
    {
        $this->assertSame(0, mlen(null));
        $this->assertSame(5, mlen('hello'));
        $this->assertSame(4, mlen('żółw'));
    }

    public function testMsub(): void
    {
        $this->assertSame('llo', msub('hello', 2));
        $this->assertSame('żó', msub('żółw', 0, 2));
        $this->assertSame('', msub(null, 0));
    }

    public function testSTrim(): void
    {
        $this->assertSame('hello', sTrim('  hello  '));
        $this->assertSame('', sTrim(null));
        $this->assertSame('42', sTrim(42));
        $this->assertSame('hello', sTrim('xxxhelloxxx', 'x'));
    }

    public function testStt(): void
    {
        // stt() is null-safe strtotime (NOT strip_tags!)
        $this->assertIsInt(stt('2024-01-01'));
        $this->assertFalse(stt(null));
        $this->assertFalse(stt(''));
    }

    public function testSStrip(): void
    {
        $this->assertSame('hello', sStrip('<b>hello</b>'));
        $this->assertSame('', sStrip(null));
    }

    public function testSCount(): void
    {
        $this->assertSame(0, sCount(null));
        $this->assertSame(2, sCount([1, 2]));
        $this->assertSame(0, sCount('string'));
        $this->assertSame(0, sCount(42));
    }

    public function testSExplode(): void
    {
        $this->assertSame(['a', 'b', 'c'], sExplode(',', 'a, b, c'));
        $this->assertSame([], sExplode(',', null));
        $this->assertSame([], sExplode(',', ''));
        $this->assertSame(['a', 'b,c'], sExplode(',', 'a,b,c', 2));
        $this->assertSame(['123'], sExplode(',', 123));
    }
}
```

**Step 2: Write HttpException test**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\HttpException;

class HttpExceptionTest extends TestCase
{
    public function testStatusCode(): void
    {
        $e = new HttpException(404, 'Not Found');
        $this->assertSame(404, $e->statusCode);
        $this->assertSame('Not Found', $e->getMessage());
    }

    public function testFactories(): void
    {
        $this->assertSame(404, HttpException::notFound()->statusCode);
        $this->assertSame(403, HttpException::forbidden()->statusCode);
        $this->assertSame(401, HttpException::unauthorized()->statusCode);
    }
}
```

**Step 3: Run tests — verify they fail**

```bash
vendor/bin/phpunit tests/Unit/HelpersTest.php tests/Unit/HttpExceptionTest.php
```

**Step 4: Implement — add to src/P1.php**

In the `namespace P1 {` block, add:

```php
// ---- Exceptions ----

class HttpException extends \RuntimeException
{
    public function __construct(
        public readonly int $statusCode,
        string $message = '',
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $statusCode, $previous);
    }

    public static function notFound(string $msg = 'Not Found'): static
    {
        return new static(404, $msg);
    }

    public static function forbidden(string $msg = 'Forbidden'): static
    {
        return new static(403, $msg);
    }

    public static function unauthorized(string $msg = 'Unauthorized'): static
    {
        return new static(401, $msg);
    }
}
```

In the `namespace {` block, add:

```php
function h(mixed $value): string
{
    if ($value === null || (!is_scalar($value) && !$value instanceof \Stringable)) {
        return '';
    }
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function ha(array $array, string|int $key, mixed $default = ''): string
{
    return h($array[$key] ?? $default);
}

function sGet(array|null $array, string|int $key, mixed $default = null): mixed
{
    if ($array === null) return $default;
    return $array[$key] ?? $default;
}

function mlen(?string $s): int
{
    return mb_strlen($s ?? '');
}

function msub(?string $s, int $start, ?int $length = null): string
{
    return mb_substr($s ?? '', $start, $length);
}

/** Trim + collapse whitespace (mixed-safe like brat) */
function sTrim(mixed $value, string $characters = " \n\r\t\v\x00"): string
{
    if ($value === null) return '';
    return trim((string)$value, $characters);
}

/** Null-safe strtotime (brat pattern — NOT strip_tags!) */
function stt(mixed $date): int|false
{
    if ($date === null || $date === '') return false;
    return strtotime((string)$date);
}

/** Strip tags + trim */
function sStrip(mixed $s): string
{
    return trim(strip_tags((string)($s ?? '')));
}

/** Null-safe count (accepts mixed like brat) */
function sCount(mixed $value): int
{
    if ($value === null) return 0;
    if (is_array($value) || $value instanceof \Countable) return count($value);
    return 0;
}

/** Null-safe explode with trim (mixed-safe like brat) */
function sExplode(string $separator, mixed $string, int $limit = PHP_INT_MAX): array
{
    if ($string === null || $string === '' || $string === []) return [];
    if (!is_scalar($string) && !$string instanceof \Stringable) return [];
    return array_map('trim', explode($separator, (string)$string, $limit));
}
```

**Step 5: Run tests — verify they pass**

```bash
vendor/bin/phpunit tests/Unit/HelpersTest.php tests/Unit/HttpExceptionTest.php
```
Expected: all pass

**Step 6: Commit**

```bash
git add src/P1.php tests/Unit/HelpersTest.php tests/Unit/HttpExceptionTest.php
git commit -m "feat: global helpers and HttpException with static factories"
```

---

## Task 3: Request + Response

**Files:**
- Modify: `src/P1.php` (add Request + Response classes)
- Create: `tests/Unit/RequestTest.php`
- Create: `tests/Unit/ResponseTest.php`

**Step 1: Write Request tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Request;

class RequestTest extends TestCase
{
    public function testFromGlobals(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/test?foo=bar';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_GET = ['foo' => 'bar'];
        $_POST = [];

        $req = Request::fromGlobals();

        $this->assertSame('GET', $req->method);
        $this->assertSame('/test', $req->path);
        $this->assertSame('bar', $req->query('foo'));
        $this->assertSame('127.0.0.1', $req->ip);
    }

    public function testManualConstruction(): void
    {
        $req = new Request(
            method: 'POST',
            path: '/submit',
            query: ['a' => '1'],
            post: ['name' => 'Joe'],
            headers: ['Content-Type' => 'application/json'],
            ip: '10.0.0.1',
        );

        $this->assertSame('POST', $req->method);
        $this->assertSame('/submit', $req->path);
        $this->assertSame('1', $req->query('a'));
        $this->assertSame('Joe', $req->post('name'));
        $this->assertSame('application/json', $req->header('Content-Type'));
        $this->assertTrue($req->isPost());
        $this->assertFalse($req->isAjax());
    }

    public function testParamsSetByRouter(): void
    {
        $req = new Request(method: 'GET', path: '/o/test-slug');
        $req->setParams(['slug' => 'test-slug']);
        $this->assertSame('test-slug', $req->param('slug'));
        $this->assertNull($req->param('missing'));
    }

    public function testOnly(): void
    {
        $req = new Request(method: 'POST', path: '/', post: ['a' => '1', 'b' => '2', 'c' => '3']);
        $result = $req->only(['a', 'c', 'missing']);
        $this->assertSame(['a' => '1', 'c' => '3', 'missing' => null], $result);
    }
}
```

**Step 2: Write Response tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Response;

class ResponseTest extends TestCase
{
    public function testDefaults(): void
    {
        $r = new Response('Hello');
        $this->assertSame(200, $r->status);
        $this->assertSame('Hello', $r->body);
    }

    public function testJson(): void
    {
        $r = Response::json(['ok' => true], 201);
        $this->assertSame(201, $r->status);
        $this->assertSame('application/json', $r->headers['Content-Type']);
        $this->assertSame('{"ok":true}', $r->body);
    }

    public function testRedirect(): void
    {
        $r = Response::redirect('/login');
        $this->assertSame(302, $r->status);
        $this->assertSame('/login', $r->headers['Location']);
    }

    public function testHtml(): void
    {
        $r = Response::html('<h1>Hi</h1>');
        $this->assertSame('text/html; charset=UTF-8', $r->headers['Content-Type']);
    }
}
```

**Step 3: Implement — add to src/P1.php namespace P1 block**

```php
// ---- HTTP ----

class Request
{
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
    ) {}

    public static function fromGlobals(): static
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', substr($key, 5));
                $name = ucwords(strtolower($name), '-');
                $headers[$name] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
        }

        return new static(
            method: strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET'),
            path: $path,
            query: $_GET,
            post: $_POST,
            server: $_SERVER,
            headers: $headers,
            cookies: $_COOKIE,
            files: $_FILES,
            ip: $_SERVER['REMOTE_ADDR'] ?? '',
            body: (string)(file_get_contents('php://input') ?: ''),
        );
    }

    public function query(string $key, mixed $default = null): mixed
    {
        return $this->query[$key] ?? $default;
    }

    public function post(string $key, mixed $default = null): mixed
    {
        return $this->post[$key] ?? $default;
    }

    public function header(string $name, ?string $default = null): ?string
    {
        // Case-insensitive header lookup (HTTP headers are case-insensitive)
        $lower = strtolower($name);
        foreach ($this->headers as $k => $v) {
            if (strtolower($k) === $lower) return $v;
        }
        return $default;
    }

    public function param(string $key, mixed $default = null): mixed
    {
        return $this->params[$key] ?? $default;
    }

    public function setParams(array $params): void
    {
        $this->params = $params;
    }

    public function only(array $keys): array
    {
        $merged = array_merge($this->query, $this->post);
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $merged[$key] ?? null;
        }
        return $result;
    }

    public function isPost(): bool { return $this->method === 'POST'; }
    public function isGet(): bool { return $this->method === 'GET'; }
    public function isAjax(): bool
    {
        return strtolower($this->header('X-Requested-With') ?? '') === 'xmlhttprequest';
    }

    public function jsonBody(): ?array
    {
        if ($this->body === '') return null;
        $decoded = json_decode($this->body, true);
        return is_array($decoded) ? $decoded : null;
    }
}

class Response
{
    public function __construct(
        public string $body = '',
        public int $status = 200,
        public array $headers = [],
    ) {}

    public static function html(string $body, int $status = 200): static
    {
        return new static($body, $status, ['Content-Type' => 'text/html; charset=UTF-8']);
    }

    public static function json(mixed $data, int $status = 200): static
    {
        return new static(
            json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
            $status,
            ['Content-Type' => 'application/json'],
        );
    }

    public static function redirect(string $url, int $status = 302): static
    {
        return new static('', $status, ['Location' => $url]);
    }

    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $name => $value) {
            header("{$name}: {$value}");
        }
        echo $this->body;
    }
}
```

**Step 4: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/RequestTest.php tests/Unit/ResponseTest.php
git add src/P1.php tests/Unit/RequestTest.php tests/Unit/ResponseTest.php
git commit -m "feat: Request and Response classes"
```

---

## Task 4: App (routing + config + middleware)

**Files:**
- Modify: `src/P1.php` (add App class with embedded router + config)
- Create: `tests/Unit/AppTest.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\App;
use P1\Request;
use P1\Response;

class AppTest extends TestCase
{
    public function testRouteRegistration(): void
    {
        $app = new App();
        $app->get('/hello', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/hello'));
        $this->assertSame(200, $response->status);
        $this->assertSame('hello world', $response->body);
    }

    public function testRouteParams(): void
    {
        $app = new App();
        $app->get('/greet/{name}', HelloStub::class, 'greet');

        $response = $app->handle(new Request(method: 'GET', path: '/greet/Joe'));
        $this->assertSame('Hello Joe', $response->body);
    }

    public function test404(): void
    {
        $app = new App();
        $response = $app->handle(new Request(method: 'GET', path: '/nope'));
        $this->assertSame(404, $response->status);
    }

    public function testGlobalMiddleware(): void
    {
        $app = new App();
        $app->addMiddleware(function (Request $req, callable $next): Response {
            $response = $next($req);
            $response->headers['X-Test'] = 'passed';
            return $response;
        });
        $app->get('/hello', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/hello'));
        $this->assertSame('passed', $response->headers['X-Test'] ?? null);
    }

    public function testRouteMiddleware(): void
    {
        $app = new App();
        $authMw = function (Request $req, callable $next): Response {
            return new Response('blocked', 403);
        };
        $app->get('/secret', HelloStub::class, 'index', mw: [$authMw]);

        $response = $app->handle(new Request(method: 'GET', path: '/secret'));
        $this->assertSame(403, $response->status);
        $this->assertSame('blocked', $response->body);
    }

    public function testPostRoute(): void
    {
        $app = new App();
        $app->post('/submit', HelloStub::class, 'submit');

        $response = $app->handle(new Request(method: 'POST', path: '/submit', post: ['val' => 'ok']));
        $this->assertSame('submitted', $response->body);
    }

    public function testNamedRouteUrl(): void
    {
        $app = new App();
        $app->get('/o/{slug}', HelloStub::class, 'index', name: 'ad.show');
        $this->assertSame('/o/test', $app->url('ad.show', ['slug' => 'test']));
    }

    public function testAjaxRoute(): void
    {
        $app = new App();
        $app->post('/api/vote', HelloStub::class, 'submit', ajax: true);

        // Non-ajax → 404
        $response = $app->handle(new Request(method: 'POST', path: '/api/vote'));
        $this->assertSame(404, $response->status);

        // Ajax → 200
        $response = $app->handle(new Request(
            method: 'POST', path: '/api/vote',
            headers: ['X-Requested-With' => 'XMLHttpRequest'],
        ));
        $this->assertSame(200, $response->status);
    }

    public function testConfig(): void
    {
        $app = new App();
        $app->loadConfig(__DIR__ . '/../fixtures/config/app.php');
        $this->assertSame('TestApp', $app->config('app_name'));
        $this->assertSame('localhost', $app->config('db.host'));
        $this->assertNull($app->config('nonexistent'));
        $this->assertSame('fallback', $app->config('nonexistent', 'fallback'));
    }
}

// Stub controller for tests
class HelloStub
{
    public Request $request;

    public function index(): Response
    {
        return new Response('hello world');
    }

    public function greet(): Response
    {
        return new Response('Hello ' . $this->request->param('name'));
    }

    public function submit(): Response
    {
        return new Response('submitted');
    }
}
```

**Step 2: Create test fixture**

`tests/fixtures/config/app.php`:
```php
<?php
return [
    'app_name' => 'TestApp',
    'debug' => 3,
    'timezone' => 'Europe/Warsaw',
    'db' => [
        'host' => 'localhost',
        'port' => 3306,
        'name' => 'test_db',
    ],
];
```

**Step 3: Implement App — add to src/P1.php namespace P1 block**

```php
// ---- Core: App (routing + config + middleware) ----

class App
{
    private static ?self $instance = null;

    // Config
    private array $configData = [];

    // Router
    /** @var array<int, array{methods: string[], pattern: string, regex: string, paramNames: string[], controller: string, action: string, middleware: array, name: ?string, ajax: bool}> */
    private array $routes = [];
    /** @var array<string, int> name → route index */
    private array $namedRoutes = [];

    // Middleware
    /** @var array<callable> */
    private array $middleware = [];

    // Services
    private ?Db $db = null;

    public function __construct()
    {
        self::$instance = $this;
    }

    public static function instance(): static
    {
        if (self::$instance === null) {
            self::$instance = new static();
        }
        return self::$instance;
    }

    // --- Config ---

    public function loadConfig(string $path): void
    {
        if (!is_file($path)) {
            throw new \RuntimeException("Config file not found: {$path}");
        }
        $values = require $path;
        if (!is_array($values)) {
            throw new \RuntimeException("Config file must return array: {$path}");
        }
        $this->configData = array_replace_recursive($this->configData, $values);
    }

    public function config(string $key, mixed $default = null): mixed
    {
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

    public function setConfig(string $key, mixed $value): void
    {
        $segments = explode('.', $key);
        if (count($segments) === 1) {
            $this->configData[$key] = $value;
            return;
        }
        $ref = &$this->configData;
        foreach ($segments as $i => $segment) {
            if ($i === count($segments) - 1) {
                $ref[$segment] = $value;
            } else {
                if (!isset($ref[$segment]) || !is_array($ref[$segment])) {
                    $ref[$segment] = [];
                }
                $ref = &$ref[$segment];
            }
        }
    }

    // --- Database ---

    public function db(): Db
    {
        if ($this->db === null) {
            $cfg = $this->config('db');
            if (!is_array($cfg)) {
                throw new \RuntimeException('Database not configured. Set "db" in config.');
            }
            $this->db = new Db($cfg);
        }
        return $this->db;
    }

    public function setDb(Db $db): void { $this->db = $db; }

    // --- Routing ---

    public function get(string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void
    {
        $this->addRoute('GET|HEAD', $path, $controller, $action, $mw, $name, $ajax);
    }

    public function post(string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void
    {
        $this->addRoute('POST', $path, $controller, $action, $mw, $name, $ajax);
    }

    public function route(string $methods, string $path, string $controller, string $action, array $mw = [], ?string $name = null, bool $ajax = false): void
    {
        $this->addRoute($methods, $path, $controller, $action, $mw, $name, $ajax);
    }

    private function addRoute(string $methods, string $pattern, string $controller, string $action, array $middleware, ?string $name, bool $ajax): void
    {
        $methodList = array_map('trim', explode('|', strtoupper($methods)));
        $paramNames = [];

        // Escape regex chars in static parts, then replace {param} and * wildcard
        $parts = preg_split('/(\{\\w+\}|\*)/', $pattern, -1, PREG_SPLIT_DELIM_CAPTURE);
        $regexParts = '';
        foreach ($parts as $part) {
            if (preg_match('/^\{(\w+)\}$/', $part, $m)) {
                $paramNames[] = $m[1];
                $regexParts .= '([^/]+)';
            } elseif ($part === '*') {
                $regexParts .= '(.*)';
            } else {
                $regexParts .= preg_quote($part, '#');
            }
        }
        $regex = $regexParts;

        $index = count($this->routes);
        $this->routes[] = [
            'methods' => $methodList,
            'pattern' => $pattern,
            'regex' => '#^' . $regex . '/?$#',
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

    private function matchRoute(string $method, string $path, bool $isAjax = false): ?array
    {
        $method = strtoupper($method);
        foreach ($this->routes as $route) {
            if (!in_array($method, $route['methods'], true)) continue;
            if ($route['ajax'] && !$isAjax) continue;
            if (!preg_match($route['regex'], $path, $matches)) continue;

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
        return null;
    }

    public function url(string $name, array $params = []): string
    {
        if (!isset($this->namedRoutes[$name])) {
            throw new \RuntimeException("Route not found: {$name}");
        }
        $route = $this->routes[$this->namedRoutes[$name]];
        $url = $route['pattern'];
        foreach ($params as $key => $value) {
            $url = str_replace('{' . $key . '}', rawurlencode((string)$value), $url);
        }
        return $url;
    }

    // --- Middleware ---

    public function addMiddleware(callable $middleware): void
    {
        $this->middleware[] = $middleware;
    }

    // --- Request handling ---

    public function handle(Request $request): Response
    {
        $handler = function (Request $req): Response {
            return $this->dispatch($req);
        };

        foreach (array_reverse($this->middleware) as $mw) {
            $next = $handler;
            $handler = function (Request $req) use ($mw, $next): Response {
                return $mw($req, $next);
            };
        }

        try {
            return $handler($request);
        } catch (HttpException $e) {
            return $this->handleHttpException($e);
        } catch (\Throwable $e) {
            return $this->handleException($e);
        }
    }

    private function dispatch(Request $request): Response
    {
        $match = $this->matchRoute($request->method, $request->path, $request->isAjax());
        if ($match === null) {
            throw HttpException::notFound();
        }

        $request->setParams($match['params']);

        // Route-level middleware chain
        $handler = function (Request $req) use ($match): Response {
            return $this->invokeController($req, $match['controller'], $match['action']);
        };
        foreach (array_reverse($match['middleware']) as $mw) {
            $next = $handler;
            $handler = function (Request $req) use ($mw, $next): Response {
                return $mw($req, $next);
            };
        }
        return $handler($request);
    }

    private function invokeController(Request $request, string $controllerClass, string $action): Response
    {
        $controller = new $controllerClass();

        if (property_exists($controller, 'request')) {
            $controller->request = $request;
        }

        // beforeRoute() — no args, request via $this->request
        if (method_exists($controller, 'beforeRoute')) {
            $result = $controller->beforeRoute();
            if ($result instanceof Response) return $result;
        }

        $result = $controller->$action();

        // afterRoute() — no args
        if (method_exists($controller, 'afterRoute')) {
            $hookResult = $controller->afterRoute();
            if ($hookResult instanceof Response) return $hookResult;
        }

        if ($result instanceof Response) return $result;
        return new Response((string)($result ?? ''));
    }

    private function handleHttpException(HttpException $e): Response
    {
        $debug = (int)$this->config('debug', 0);
        $message = $debug >= 3 ? $e->getMessage() : match ($e->statusCode) {
            404 => 'Nie znaleziono',
            403 => 'Brak dostępu',
            401 => 'Wymagane logowanie',
            default => 'Błąd serwera',
        };
        return new Response($message, $e->statusCode);
    }

    private function handleException(\Throwable $e): Response
    {
        $debug = (int)$this->config('debug', 0);
        $body = $debug >= 3
            ? $e->getMessage() . "\n" . $e->getTraceAsString()
            : 'Wystąpił błąd serwera.';
        return new Response($body, 500);
    }

    public function run(): void
    {
        $request = Request::fromGlobals();
        $response = $this->handle($request);
        $response->send();
    }
}
```

**Step 4: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/AppTest.php
git add src/P1.php tests/Unit/AppTest.php tests/fixtures/
git commit -m "feat: App with embedded routing, config, and middleware pipeline"
```

---

## Task 5: Db (PDO wrapper)

**Files:**
- Modify: `src/P1.php` (add Db class)
- Create: `tests/Unit/DbTest.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Db;

class DbTest extends TestCase
{
    private Db $db;

    protected function setUp(): void
    {
        $this->db = new Db(['dsn' => 'sqlite::memory:']);
        $this->db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)');
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Joe', 'joe@x.com']);
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Ann', 'ann@x.com']);
    }

    public function testVar(): void
    {
        $this->assertEquals(2, $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testVarNull(): void
    {
        $this->assertNull($this->db->var('SELECT name FROM users WHERE id = ?', [999]));
    }

    public function testRow(): void
    {
        $this->assertSame('Joe', $this->db->row('SELECT * FROM users WHERE id = ?', [1])['name']);
    }

    public function testRowNull(): void
    {
        $this->assertNull($this->db->row('SELECT * FROM users WHERE id = ?', [999]));
    }

    public function testResults(): void
    {
        $rows = $this->db->results('SELECT * FROM users ORDER BY id');
        $this->assertCount(2, $rows);
    }

    public function testCol(): void
    {
        $this->assertSame(['Joe', 'Ann'], $this->db->col('SELECT name FROM users ORDER BY id'));
    }

    public function testExecReturnsAffectedRows(): void
    {
        $this->assertSame(1, $this->db->exec('UPDATE users SET name = ? WHERE id = ?', ['Bob', 1]));
    }

    public function testInsertGetId(): void
    {
        $this->assertSame(3, $this->db->insertGetId('INSERT INTO users (name, email) VALUES (?, ?)', ['New', 'new@x.com']));
    }

    public function testTransaction(): void
    {
        $this->db->begin();
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Tx', 'tx@x.com']);
        $this->db->rollback();
        $this->assertEquals(2, $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testPlaceholders(): void
    {
        $this->assertSame('?, ?, ?', $this->db->placeholders([1, 2, 3]));
    }

    public function testStringParam(): void
    {
        $row = $this->db->row('SELECT * FROM users WHERE name = ?', 'Joe');
        $this->assertSame('Joe', $row['name']);
    }
}
```

**Step 2: Implement Db — add to src/P1.php**

```php
// ---- Database ----

class Db
{
    private \PDO $pdo;

    public function __construct(array $config)
    {
        $dsn = $config['dsn'] ?? sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $config['host'] ?? 'localhost',
            $config['port'] ?? 3306,
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
    }

    public function pdo(): \PDO { return $this->pdo; }

    private function norm(array|string|null $p): ?array
    {
        return is_string($p) ? [$p] : $p;
    }

    public function exec(string $sql, array|string|null $params = null): int|array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($this->norm($params));
        return stripos(ltrim($sql), 'SELECT') === 0 ? $stmt->fetchAll() : $stmt->rowCount();
    }

    public function var(string $sql, array|string|null $params = null): mixed
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($this->norm($params));
        $row = $stmt->fetch(\PDO::FETCH_NUM);
        return $row ? $row[0] : null;
    }

    public function row(string $sql, array|string|null $params = null): ?array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($this->norm($params));
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function results(string $sql, array|string|null $params = null): array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($this->norm($params));
        return $stmt->fetchAll();
    }

    public function col(string $sql, array|string|null $params = null): array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($this->norm($params));
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    }

    public function insertGetId(string $sql, array|string|null $params = null): int
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($this->norm($params));
        return (int)$this->pdo->lastInsertId();
    }

    public function begin(): bool { return $this->pdo->beginTransaction(); }
    public function commit(): bool { return $this->pdo->commit(); }
    public function rollback(): bool { return $this->pdo->rollBack(); }

    public function placeholders(array $items): string
    {
        return implode(', ', array_fill(0, count($items), '?'));
    }
}
```

**Step 3: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/DbTest.php
git add src/P1.php tests/Unit/DbTest.php
git commit -m "feat: Db wrapper with var/row/results/col/exec, string params"
```

---

## Task 6: View (pure PHP templates)

**Files:**
- Modify: `src/P1.php` (add View class)
- Create: `tests/Unit/ViewTest.php`
- Create: `tests/fixtures/templates/simple.php`
- Create: `tests/fixtures/templates/layout.php`
- Create: `tests/fixtures/templates/with_layout.php`
- Create: `tests/fixtures/templates/with_partial.php`
- Create: `tests/fixtures/templates/_item.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\View;

class ViewTest extends TestCase
{
    private View $view;

    protected function setUp(): void
    {
        $this->view = new View(__DIR__ . '/../fixtures/templates');
    }

    public function testRenderSimple(): void
    {
        $html = $this->view->render('simple.php', ['name' => 'Joe']);
        $this->assertStringContainsString('Hello Joe', $html);
    }

    public function testRenderWithLayout(): void
    {
        $html = $this->view->render('with_layout.php', ['title' => 'Test']);
        $this->assertStringContainsString('<html>', $html);
        $this->assertStringContainsString('<title>Test</title>', $html);
        $this->assertStringContainsString('Content here', $html);
    }

    public function testVariablesEscaped(): void
    {
        $html = $this->view->render('simple.php', ['name' => '<script>']);
        $this->assertStringNotContainsString('<script>', $html);
    }

    public function testPartial(): void
    {
        $html = $this->view->render('with_partial.php', ['items' => ['a', 'b']]);
        $this->assertStringContainsString('item: a', $html);
        $this->assertStringContainsString('item: b', $html);
    }
}
```

**Step 2: Create test templates**

`tests/fixtures/templates/simple.php`:
```php
<p>Hello <?= h($name) ?></p>
```

`tests/fixtures/templates/layout.php`:
```php
<html><head><title><?= h($pageTitle ?? '') ?></title></head><body><?= $content ?></body></html>
```

`tests/fixtures/templates/with_layout.php`:
```php
<?php $view->layout('layout.php', ['pageTitle' => $title]) ?>
<p>Content here</p>
```

`tests/fixtures/templates/with_partial.php`:
```php
<?php foreach ($items as $item): ?>
    <?= $view->partial('_item.php', ['item' => $item]) ?>
<?php endforeach; ?>
```

`tests/fixtures/templates/_item.php`:
```php
<span>item: <?= h($item) ?></span>
```

**Step 3: Implement View — add to src/P1.php**

```php
// ---- View (pure PHP templates) ----

class View
{
    private ?string $layoutFile = null;
    private array $layoutData = [];

    public function __construct(
        private readonly string $basePath,
    ) {}

    public function render(string $template, array $data = []): string
    {
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

    public function layout(string $file, array $data = []): void
    {
        $this->layoutFile = $file;
        $this->layoutData = $data;
    }

    public function partial(string $template, array $data = []): string
    {
        return $this->renderFile($template, $data);
    }

    private function renderFile(string $template, array $data): string
    {
        $filePath = $this->basePath . '/' . $template;
        if (!is_file($filePath)) {
            throw new \RuntimeException("Template not found: {$filePath}");
        }
        $view = $this;
        extract($data);
        ob_start();
        include $filePath;
        return ob_get_clean();
    }
}
```

**Step 4: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/ViewTest.php
git add src/P1.php tests/Unit/ViewTest.php tests/fixtures/templates/
git commit -m "feat: View with pure PHP templates, layouts, partials"
```

---

## Task 7: Session (DB with advisory locking)

**Files:**
- Modify: `src/P1.php` (add Session class)
- Create: `tests/Unit/SessionTest.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Session;
use P1\Db;

class SessionTest extends TestCase
{
    private Db $db;

    protected function setUp(): void
    {
        $this->db = new Db(['dsn' => 'sqlite::memory:']);
        $this->db->exec('CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY,
            data TEXT NOT NULL DEFAULT "",
            ip TEXT NOT NULL DEFAULT "",
            agent TEXT NOT NULL DEFAULT "",
            stamp INTEGER NOT NULL DEFAULT 0
        )');
    }

    public function testWriteAndRead(): void
    {
        $session = new Session($this->db, advisory: false);
        $session->write('sid1', 'test_data');
        $this->assertSame('test_data', $session->read('sid1'));
    }

    public function testReadMissing(): void
    {
        $session = new Session($this->db, advisory: false);
        $this->assertSame('', $session->read('nonexistent'));
    }

    public function testDestroy(): void
    {
        $session = new Session($this->db, advisory: false);
        $session->write('sid1', 'data');
        $session->destroy('sid1');
        $this->assertSame('', $session->read('sid1'));
    }

    public function testGc(): void
    {
        $session = new Session($this->db, advisory: false);
        $this->db->exec(
            'INSERT INTO sessions (session_id, data, stamp) VALUES (?, ?, ?)',
            ['old', 'data', time() - 7200]
        );
        $session->write('new', 'data');

        $cleaned = $session->gc(3600);
        $this->assertSame(1, $cleaned);
        $this->assertSame('data', $session->read('new'));
    }
}
```

**Step 2: Implement Session — add to src/P1.php**

```php
// ---- Session (DB with advisory locking) ----

class Session implements \SessionHandlerInterface
{
    private ?string $lockName = null;

    public function __construct(
        private readonly Db $db,
        private readonly bool $advisory = true,
    ) {}

    public function register(array $cookieParams = []): void
    {
        session_set_save_handler($this, true);
        $defaults = [
            'lifetime' => 7200,
            'path' => '/',
            'httponly' => true,
            'samesite' => 'Lax',
        ];
        session_set_cookie_params(array_merge($defaults, $cookieParams));
    }

    public function open(string $path, string $name): bool { return true; }

    public function read(string $id): string|false
    {
        if ($this->advisory) $this->acquireLock($id);
        try {
            $data = $this->db->var('SELECT data FROM sessions WHERE session_id = ?', [$id]);
            return is_string($data) ? $data : '';
        } catch (\Throwable $e) {
            $this->releaseLock();
            throw $e;
        }
    }

    public function write(string $id, string $data): bool
    {
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 5000);
            $stamp = time();

            $driver = $this->db->pdo()->getAttribute(\PDO::ATTR_DRIVER_NAME);
            if ($driver === 'sqlite') {
                $this->db->exec(
                    'INSERT OR REPLACE INTO sessions (session_id, data, ip, agent, stamp) VALUES (?, ?, ?, ?, ?)',
                    [$id, $data, $ip, $agent, $stamp]
                );
            } else {
                $this->db->exec(
                    'INSERT INTO sessions (session_id, data, ip, agent, stamp) VALUES (?, ?, ?, ?, ?) '
                    . 'ON DUPLICATE KEY UPDATE data=VALUES(data), ip=VALUES(ip), agent=VALUES(agent), stamp=VALUES(stamp)',
                    [$id, $data, $ip, $agent, $stamp]
                );
            }
        } finally {
            $this->releaseLock();
        }
        return true;
    }

    public function close(): bool
    {
        $this->releaseLock();
        return true;
    }

    public function destroy(string $id): bool
    {
        $this->db->exec('DELETE FROM sessions WHERE session_id = ?', [$id]);
        $this->releaseLock();
        return true;
    }

    public function gc(int $max_lifetime): int|false
    {
        return $this->db->exec('DELETE FROM sessions WHERE stamp < ?', [time() - $max_lifetime]);
    }

    private function acquireLock(string $id): void
    {
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

    private function releaseLock(): void
    {
        if ($this->lockName !== null) {
            try {
                $this->db->var('SELECT RELEASE_LOCK(?)', [$this->lockName]);
            } catch (\Throwable) {}
            $this->lockName = null;
        }
    }
}
```

**Step 3: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/SessionTest.php
git add src/P1.php tests/Unit/SessionTest.php
git commit -m "feat: DB Session with advisory locking and SQLite compat"
```

---

## Task 8: Csrf + Flash

**Files:**
- Modify: `src/P1.php` (add Csrf + Flash classes)
- Create: `tests/Unit/CsrfTest.php`
- Create: `tests/Unit/FlashTest.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Csrf;

class CsrfTest extends TestCase
{
    protected function setUp(): void { $_SESSION = []; }

    public function testGenerateToken(): void
    {
        $token = Csrf::token();
        $this->assertSame(64, strlen($token));
        $this->assertSame($token, Csrf::token());
    }

    public function testValidateCorrect(): void
    {
        $this->assertTrue(Csrf::validate(Csrf::token()));
    }

    public function testValidateWrong(): void
    {
        Csrf::token();
        $this->assertFalse(Csrf::validate('wrong'));
    }

    public function testValidateEmpty(): void
    {
        $this->assertFalse(Csrf::validate(null));
        $this->assertFalse(Csrf::validate(''));
    }

    public function testHiddenInput(): void
    {
        $html = Csrf::hiddenInput();
        $this->assertStringContainsString('type="hidden"', $html);
        $this->assertStringContainsString('name="csrf_token"', $html);
    }

    public function testActionNonce(): void
    {
        $nonce = Csrf::nonce('delete');
        $this->assertSame(64, strlen($nonce));
        $this->assertSame($nonce, Csrf::nonce('delete'));
        $this->assertNotSame($nonce, Csrf::nonce('edit'));
    }

    public function testVerifyNonce(): void
    {
        $nonce = Csrf::nonce('submit');
        $this->assertTrue(Csrf::verifyNonce('submit', $nonce));
        $this->assertFalse(Csrf::verifyNonce('submit', 'wrong'));
        $this->assertFalse(Csrf::verifyNonce('other', $nonce));
    }
}
```

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Flash;

class FlashTest extends TestCase
{
    protected function setUp(): void { $_SESSION = []; }

    public function testAddAndGet(): void
    {
        $flash = new Flash();
        $flash->add('success', 'Saved!');
        $flash->add('error', 'Oops');

        $msgs = $flash->get();
        $this->assertCount(2, $msgs);
        $this->assertSame('success', $msgs[0]['type']);
    }

    public function testGetClearsMessages(): void
    {
        $flash = new Flash();
        $flash->add('info', 'Note');
        $flash->get();
        $this->assertEmpty($flash->get());
    }

    public function testHas(): void
    {
        $flash = new Flash();
        $this->assertFalse($flash->has());
        $flash->add('info', 'x');
        $this->assertTrue($flash->has());
    }
}
```

**Step 2: Implement — add to src/P1.php**

```php
// ---- Auth / UX ----

class Csrf
{
    private const SESSION_KEY = '_csrf_token';
    private const SECRET_KEY = '_csrf_secret';
    public const FIELD_NAME = 'csrf_token';

    public static function token(): string
    {
        if (empty($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }
        return $_SESSION[self::SESSION_KEY];
    }

    public static function validate(?string $token): bool
    {
        if ($token === null || $token === '') return false;
        $stored = $_SESSION[self::SESSION_KEY] ?? '';
        if ($stored === '') return false;
        return hash_equals($stored, $token);
    }

    public static function nonce(string $action): string
    {
        if (empty($_SESSION[self::SECRET_KEY])) {
            $_SESSION[self::SECRET_KEY] = bin2hex(random_bytes(32));
        }
        return hash_hmac('sha256', $action, $_SESSION[self::SECRET_KEY]);
    }

    public static function verifyNonce(string $action, ?string $token): bool
    {
        if ($token === null || $token === '') return false;
        return hash_equals(self::nonce($action), $token);
    }

    public static function hiddenInput(?string $action = null): string
    {
        $token = $action !== null ? self::nonce($action) : self::token();
        $escaped = htmlspecialchars($token, ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="' . self::FIELD_NAME . '" value="' . $escaped . '">';
    }
}

class Flash
{
    private const SESSION_KEY = '_flash_messages';

    public function add(string $type, string $text): void
    {
        $_SESSION[self::SESSION_KEY][] = ['type' => $type, 'text' => $text];
    }

    public function get(): array
    {
        $messages = $_SESSION[self::SESSION_KEY] ?? [];
        unset($_SESSION[self::SESSION_KEY]);
        return $messages;
    }

    public function has(): bool
    {
        return !empty($_SESSION[self::SESSION_KEY]);
    }

    public function success(string $text): void { $this->add('success', $text); }
    public function error(string $text): void { $this->add('error', $text); }
    public function warning(string $text): void { $this->add('warning', $text); }
    public function info(string $text): void { $this->add('info', $text); }
}
```

**Step 3: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/CsrfTest.php tests/Unit/FlashTest.php
git add src/P1.php tests/Unit/CsrfTest.php tests/Unit/FlashTest.php
git commit -m "feat: CSRF (global + action nonce) and Flash messages"
```

---

## Task 9: Controller (base class)

**Files:**
- Modify: `src/P1.php` (add Controller class)
- Create: `tests/Unit/ControllerTest.php`

**Step 1: Write tests**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Controller;
use P1\App;
use P1\Request;
use P1\Response;
use P1\Flash;

class ControllerTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
        new App();
    }

    public function testJson(): void
    {
        $ctrl = new class extends Controller {
            public function test(): Response { return $this->json(['ok' => true]); }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');
        $this->assertSame('{"ok":true}', $ctrl->test()->body);
    }

    public function testJsonError(): void
    {
        $ctrl = new class extends Controller {
            public function test(): Response { return $this->jsonError('Bad', 422); }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');
        $this->assertSame(422, $ctrl->test()->status);
    }

    public function testFlashAndRedirect(): void
    {
        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->flashAndRedirect('success', 'Done!', '/home');
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');

        $response = $ctrl->test();
        $this->assertSame(302, $response->status);
        $this->assertSame('/home', $response->headers['Location']);
        $this->assertSame('Done!', (new Flash())->get()[0]['text']);
    }

    public function testParam(): void
    {
        $ctrl = new class extends Controller {
            public function test(): string { return $this->param('slug', 'default'); }
        };
        $req = new Request(method: 'GET', path: '/');
        $req->setParams(['slug' => 'hello']);
        $ctrl->request = $req;
        $this->assertSame('hello', $ctrl->test());
    }

    public function testPaginate(): void
    {
        $ctrl = new class extends Controller {
            public function test(): array { return $this->paginate(100, 20); }
        };
        $ctrl->request = new Request(method: 'GET', path: '/', query: ['page' => '3']);
        $p = $ctrl->test();
        $this->assertSame(3, $p['page']);
        $this->assertSame(40, $p['offset']);
        $this->assertSame(5, $p['total_pages']);
    }
}
```

**Step 2: Implement Controller — add to src/P1.php**

```php
// ---- Controller ----

abstract class Controller
{
    public Request $request;

    protected function render(string $template, array $data = []): Response
    {
        $app = App::instance();
        $viewPath = $app->config('view_path', 'templates');
        $view = new View($viewPath);

        $data['flash'] = (new Flash())->get();
        $data['csrf_token'] = Csrf::token();
        $data['csrf_input'] = Csrf::hiddenInput();

        return Response::html($view->render($template, $data));
    }

    protected function json(mixed $data, int $status = 200): Response
    {
        return Response::json($data, $status);
    }

    protected function jsonSuccess(array $data = []): Response
    {
        return Response::json(array_merge(['success' => true], $data));
    }

    protected function jsonError(string $message, int $status = 400, array $extra = []): Response
    {
        return Response::json(
            array_merge(['success' => false, 'message' => $message], $extra),
            $status,
        );
    }

    protected function flash(string $type, string $message): void
    {
        (new Flash())->add($type, $message);
    }

    protected function redirect(string $url, int $status = 302): Response
    {
        return Response::redirect($url, $status);
    }

    protected function flashAndRedirect(string $type, string $message, string $url): Response
    {
        $this->flash($type, $message);
        return $this->redirect($url);
    }

    protected function requireAuth(): void
    {
        if (!$this->currentUser()) {
            $this->flash('warning', 'Musisz się zalogować.');
            throw HttpException::unauthorized();
        }
    }

    protected function requireAdmin(): void
    {
        $this->requireAuth();
        if (($this->currentUser()['role'] ?? '') !== 'admin') {
            throw HttpException::forbidden();
        }
    }

    protected function currentUser(): ?array
    {
        return $_SESSION['user'] ?? null;
    }

    protected function currentUserId(): int
    {
        return (int)($this->currentUser()['id'] ?? 0);
    }

    protected function isAuthenticated(): bool
    {
        return $this->currentUser() !== null;
    }

    protected function validateCsrf(): void
    {
        $token = $this->request->post(Csrf::FIELD_NAME)
            ?? $this->request->header('X-Csrf-Token');
        if (!Csrf::validate($token)) {
            throw HttpException::forbidden('Sesja wygasła. Odśwież stronę.');
        }
    }

    protected function param(string $key, mixed $default = null): mixed
    {
        return $this->request->param($key, $default);
    }

    protected function postData(array $keys): array
    {
        return $this->request->only($keys);
    }

    protected function paginate(int $total, int $perPage = 20): array
    {
        $page = max(1, (int)($this->request->query('page') ?? 1));
        $totalPages = max(1, (int)ceil($total / $perPage));
        $offset = ($page - 1) * $perPage;

        return [
            'page' => $page,
            'offset' => $offset,
            'total_pages' => $totalPages,
            'per_page' => $perPage,
            'total' => $total,
            'limit' => "LIMIT {$perPage} OFFSET {$offset}",
        ];
    }
}
```

**Step 3: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/ControllerTest.php
git add src/P1.php tests/Unit/ControllerTest.php
git commit -m "feat: base Controller with render, json, flash, auth, csrf, paginate"
```

---

## Task 10: Utilities (Log, Validator, Cache, Mail)

**Files:**
- Modify: `src/P1.php` (add 4 utility classes)
- Create: `tests/Unit/LogTest.php`
- Create: `tests/Unit/ValidatorTest.php`
- Create: `tests/Unit/CacheTest.php`

**Step 1: Add all 4 classes to src/P1.php**

```php
// ---- Utilities ----

class Log
{
    private const LEVELS = ['trace' => 1, 'debug' => 3, 'info' => 5, 'warn' => 7, 'error' => 9];
    private static ?string $basePath = null;
    private static int $minLevel = 5;

    public static function init(string $basePath, int $minLevel = 5): void
    {
        self::$basePath = rtrim($basePath, '/');
        self::$minLevel = $minLevel;
    }

    public static function trace(string $msg, array $ctx = []): void { self::log('trace', $msg, $ctx); }
    public static function debug(string $msg, array $ctx = []): void { self::log('debug', $msg, $ctx); }
    public static function info(string $msg, array $ctx = []): void { self::log('info', $msg, $ctx); }
    public static function warn(string $msg, array $ctx = []): void { self::log('warn', $msg, $ctx); }
    public static function error(string $msg, array $ctx = []): void { self::log('error', $msg, $ctx); }

    public static function toFile(string $filename, string $message): void
    {
        if (self::$basePath === null) return;
        $path = self::$basePath . '/' . date('Y') . '_' . $filename;
        @file_put_contents($path, date('[Y-m-d H:i:s] ') . $message . "\n", FILE_APPEND | LOCK_EX);
    }

    private static function log(string $level, string $msg, array $ctx): void
    {
        if ((self::LEVELS[$level] ?? 9) < self::$minLevel) return;
        $line = strtoupper($level) . ' ' . $msg;
        if ($ctx) $line .= ' ' . json_encode($ctx, JSON_UNESCAPED_UNICODE);
        self::toFile('app.log', $line);
    }
}

class Validator
{
    public static function email(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function phone(string $value): bool
    {
        $normalized = preg_replace('/[\s\-]/', '', $value);
        return (bool)preg_match('/^(\+48)?[0-9]{9}$/', $normalized);
    }

    public static function postcode(string $value): bool
    {
        return (bool)preg_match('/^[0-9]{2}-[0-9]{3}$/', $value);
    }

    public static function length(string $value, int $min, int $max): ?string
    {
        $len = mb_strlen($value);
        if ($len < $min) return "Minimum {$min} znaków";
        if ($len > $max) return "Maksimum {$max} znaków";
        return null;
    }

    public static function required(mixed $value): bool
    {
        return $value !== null && $value !== '';
    }

    public static function intRange(mixed $value, int $min, int $max): bool
    {
        $int = is_int($value) ? $value : (is_numeric($value) ? (int)$value : null);
        return $int !== null && $int >= $min && $int <= $max;
    }

    public static function slug(string $value, int $maxLength = 100): ?string
    {
        if (mb_strlen($value) > $maxLength) return "Slug max {$maxLength} znaków";
        if (!preg_match('/^[a-z0-9-]+$/', $value)) return 'Slug: tylko małe litery, cyfry i myślniki';
        return null;
    }

    public static function validate(array $rules, array $data): array
    {
        $errors = [];
        foreach ($rules as $field => $fieldRules) {
            $value = $data[$field] ?? null;
            foreach ((array)$fieldRules as $rule) {
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

class Cache
{
    public function __construct(private readonly string $dir)
    {
        if (!is_dir($this->dir)) mkdir($this->dir, 0755, true);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if (function_exists('apcu_exists') && apcu_exists($key)) {
            return apcu_fetch($key);
        }
        $path = $this->path($key);
        if (!is_file($path)) return $default;
        try {
            $data = @unserialize(file_get_contents($path));
        } catch (\Throwable) {
            @unlink($path);
            return $default;
        }
        if (!is_array($data) || !isset($data['value'])) {
            @unlink($path);
            return $default;
        }
        if ($data['ttl'] > 0 && $data['time'] + $data['ttl'] < time()) {
            unlink($path);
            return $default;
        }
        return $data['value'];
    }

    public function set(string $key, mixed $value, int $ttl = 0): void
    {
        if (function_exists('apcu_store') && $ttl > 0) {
            apcu_store($key, $value, $ttl);
        }
        file_put_contents($this->path($key), serialize(['value' => $value, 'ttl' => $ttl, 'time' => time()]), LOCK_EX);
    }

    public function delete(string $key): void
    {
        if (function_exists('apcu_delete')) apcu_delete($key);
        $path = $this->path($key);
        if (is_file($path)) unlink($path);
    }

    public function clear(): void
    {
        foreach (glob($this->dir . '/*.cache') as $file) unlink($file);
    }

    /** Rate limiter: returns seconds until retry, or null if allowed */
    public function rateCheck(string $scope, string $id, int $max, int $window): ?int
    {
        $key = "rl:{$scope}:{$id}";
        $data = $this->get($key);
        if ($data === null) {
            $this->set($key, ['count' => 1, 'start' => time()], $window);
            return null;
        }
        $elapsed = time() - $data['start'];
        if ($elapsed >= $window) {
            $this->set($key, ['count' => 1, 'start' => time()], $window);
            return null;
        }
        if ($data['count'] >= $max) return $window - $elapsed;
        $data['count']++;
        $this->set($key, $data, $window);
        return null;
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . md5($key) . '.cache';
    }
}

class Mail
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $user,
        private readonly string $pass,
        private readonly string $fromEmail,
        private readonly string $fromName = '',
    ) {}

    public static function fromConfig(array $config): static
    {
        return new static(
            host: $config['host'],
            port: (int)$config['port'],
            user: $config['user'],
            pass: $config['pass'],
            fromEmail: $config['from_email'],
            fromName: $config['from_name'] ?? '',
        );
    }

    public function send(string $to, string $subject, string $body, bool $html = true): bool
    {
        $socket = @fsockopen($this->host, $this->port, $errno, $errstr, 10);
        if (!$socket) return false;

        try {
            $this->read($socket);
            $this->cmd($socket, "EHLO localhost");
            $this->cmd($socket, "STARTTLS");
            stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT);
            $this->cmd($socket, "EHLO localhost");
            $this->cmd($socket, "AUTH LOGIN");
            $this->cmd($socket, base64_encode($this->user));
            $this->cmd($socket, base64_encode($this->pass));
            $this->cmd($socket, "MAIL FROM:<{$this->fromEmail}>");
            $this->cmd($socket, "RCPT TO:<{$to}>");
            $this->cmd($socket, "DATA");

            $contentType = $html ? 'text/html; charset=UTF-8' : 'text/plain; charset=UTF-8';
            $from = $this->fromName ? "{$this->fromName} <{$this->fromEmail}>" : $this->fromEmail;

            $message = "From: {$from}\r\nTo: {$to}\r\nSubject: {$subject}\r\n"
                . "MIME-Version: 1.0\r\nContent-Type: {$contentType}\r\n\r\n" . $body;

            $this->cmd($socket, $message . "\r\n.");
            $this->cmd($socket, "QUIT");
            return true;
        } catch (\Throwable) {
            return false;
        } finally {
            fclose($socket);
        }
    }

    private function cmd($socket, string $command): string
    {
        fwrite($socket, $command . "\r\n");
        return $this->read($socket);
    }

    private function read($socket): string
    {
        $response = '';
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $response;
    }
}
```

**Step 2: Write tests for Log, Validator, Cache**

`tests/Unit/LogTest.php`:
```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Log;

class LogTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/p1_log_test_' . uniqid();
        mkdir($this->tmpDir);
        Log::init($this->tmpDir, 1);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->tmpDir . '/*'));
        rmdir($this->tmpDir);
    }

    public function testWritesLogFile(): void
    {
        Log::info('test message', ['key' => 'val']);
        $files = glob($this->tmpDir . '/*app.log');
        $this->assertNotEmpty($files);
        $content = file_get_contents($files[0]);
        $this->assertStringContainsString('INFO test message', $content);
        $this->assertStringContainsString('"key":"val"', $content);
    }

    public function testLevelFiltering(): void
    {
        Log::init($this->tmpDir, 7);
        Log::debug('should not appear');
        Log::warn('should appear');
        $files = glob($this->tmpDir . '/*app.log');
        $content = $files ? file_get_contents($files[0]) : '';
        $this->assertStringNotContainsString('DEBUG', $content);
        $this->assertStringContainsString('WARN', $content);
    }
}
```

`tests/Unit/ValidatorTest.php`:
```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Validator;

class ValidatorTest extends TestCase
{
    public function testEmail(): void
    {
        $this->assertTrue(Validator::email('a@b.com'));
        $this->assertFalse(Validator::email('notanemail'));
    }

    public function testPhone(): void
    {
        $this->assertTrue(Validator::phone('123456789'));
        $this->assertTrue(Validator::phone('+48 123 456 789'));
        $this->assertFalse(Validator::phone('12345'));
    }

    public function testPostcode(): void
    {
        $this->assertTrue(Validator::postcode('30-002'));
        $this->assertFalse(Validator::postcode('3002'));
    }

    public function testLength(): void
    {
        $this->assertNull(Validator::length('hello', 3, 10));
        $this->assertNotNull(Validator::length('hi', 3, 10));
    }

    public function testRequired(): void
    {
        $this->assertTrue(Validator::required('x'));
        $this->assertFalse(Validator::required(''));
        $this->assertFalse(Validator::required(null));
    }

    public function testIntRange(): void
    {
        $this->assertTrue(Validator::intRange(5, 1, 10));
        $this->assertFalse(Validator::intRange(11, 1, 10));
    }
}
```

`tests/Unit/CacheTest.php`:
```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;
use P1\Cache;

class CacheTest extends TestCase
{
    private string $dir;
    private Cache $cache;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/p1_cache_test_' . uniqid();
        $this->cache = new Cache($this->dir);
    }

    protected function tearDown(): void
    {
        $this->cache->clear();
        if (is_dir($this->dir)) rmdir($this->dir);
    }

    public function testSetAndGet(): void
    {
        $this->cache->set('key', 'value');
        $this->assertSame('value', $this->cache->get('key'));
    }

    public function testDefault(): void
    {
        $this->assertSame('fallback', $this->cache->get('nope', 'fallback'));
    }

    public function testDelete(): void
    {
        $this->cache->set('k', 'v');
        $this->cache->delete('k');
        $this->assertNull($this->cache->get('k'));
    }

    public function testRateCheck(): void
    {
        $this->assertNull($this->cache->rateCheck('login', '1.2.3.4', 3, 60));
        $this->assertNull($this->cache->rateCheck('login', '1.2.3.4', 3, 60));
        $this->assertNull($this->cache->rateCheck('login', '1.2.3.4', 3, 60));
        $retry = $this->cache->rateCheck('login', '1.2.3.4', 3, 60);
        $this->assertIsInt($retry);
        $this->assertGreaterThan(0, $retry);
    }
}
```

**Step 3: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/LogTest.php tests/Unit/ValidatorTest.php tests/Unit/CacheTest.php
git add src/P1.php tests/Unit/LogTest.php tests/Unit/ValidatorTest.php tests/Unit/CacheTest.php
git commit -m "feat: Log, Validator, Cache (with rate limiting), Mail"
```

---

## Task 11: P1 Facade

**Files:**
- Modify: `src/P1.php` (add P1 facade class)
- Create: `tests/Unit/P1FacadeTest.php`

**Step 1: Implement P1 Facade — add to src/P1.php (last class in namespace P1 block)**

```php
// ---- Facade ----

class P1
{
    // Field constants
    public const ID = 'id';
    public const SLUG = 'slug';
    public const NAME = 'name';
    public const EMAIL = 'email';
    public const PHONE = 'phone';
    public const PASSWORD = 'password';
    public const ROLE = 'role';
    public const STATUS = 'status';
    public const TITLE = 'title';
    public const DESCRIPTION = 'description';
    public const PRICE = 'price';
    public const DATE_ADDED = 'date_added';

    public const ROLE_ADMIN = 'admin';
    public const ROLE_MODERATOR = 'moderator';
    public const ROLE_USER = 'user';

    public static function app(): App { return App::instance(); }
    public static function config(string $key, mixed $default = null): mixed { return self::app()->config($key, $default); }
    public static function db(): Db { return self::app()->db(); }
    public static function url(string $name, array $params = []): string { return self::app()->url($name, $params); }

    public static function var(string $sql, array|string|null $params = null): mixed { return self::db()->var($sql, $params); }
    public static function row(string $sql, array|string|null $params = null): ?array { return self::db()->row($sql, $params); }
    public static function results(string $sql, array|string|null $params = null): array { return self::db()->results($sql, $params); }
    public static function col(string $sql, array|string|null $params = null): array { return self::db()->col($sql, $params); }
    public static function exec(string $sql, array|string|null $params = null): int|array { return self::db()->exec($sql, $params); }
    public static function insertGetId(string $sql, array|string|null $params = null): int { return self::db()->insertGetId($sql, $params); }

    public static function flash(): Flash { return new Flash(); }
}
```

**Step 2: Write test**

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;

class P1FacadeTest extends TestCase
{
    public function testAppReturnsInstance(): void
    {
        $app = new \P1\App();
        $this->assertSame($app, \P1\P1::app());
    }

    public function testConfigViaFacade(): void
    {
        $app = new \P1\App();
        $app->setConfig('test_key', 'test_val');
        $this->assertSame('test_val', \P1\P1::config('test_key'));
    }

    public function testClassAlias(): void
    {
        class_alias(\P1\P1::class, 'P1Alias');
        new \P1\App();
        $this->assertSame(\P1\P1::app(), \P1Alias::app());
    }
}
```

**Step 3: Run tests, commit**

```bash
vendor/bin/phpunit tests/Unit/P1FacadeTest.php
git add src/P1.php tests/Unit/P1FacadeTest.php
git commit -m "feat: P1 facade with constants and static shortcuts"
```

---

## Task 12: Integration Tests

**Files:**
- Create: `tests/Integration/FullCycleTest.php`

```php
<?php
declare(strict_types=1);
namespace P1\Tests\Integration;

use PHPUnit\Framework\TestCase;
use P1\App;
use P1\Controller;
use P1\Request;
use P1\Response;

class FullCycleTest extends TestCase
{
    public function testFullGetRequest(): void
    {
        $_SESSION = [];
        $app = new App();
        $app->get('/', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/'));
        $this->assertSame(200, $response->status);
        $this->assertStringContainsString('Welcome', $response->body);
    }

    public function testRouteParams(): void
    {
        $_SESSION = [];
        $app = new App();
        $app->get('/user/{id}', TestUserCtrl::class, 'show');

        $response = $app->handle(new Request(method: 'GET', path: '/user/42'));
        $this->assertStringContainsString('User 42', $response->body);
    }

    public function test404(): void
    {
        $app = new App();
        $response = $app->handle(new Request(method: 'GET', path: '/nonexistent'));
        $this->assertSame(404, $response->status);
    }

    public function testGlobalMiddleware(): void
    {
        $_SESSION = [];
        $app = new App();
        $app->addMiddleware(function (Request $r, callable $next): Response {
            $resp = $next($r);
            $resp->headers['X-Powered-By'] = 'P1';
            return $resp;
        });
        $app->get('/', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/'));
        $this->assertSame('P1', $response->headers['X-Powered-By']);
    }

    public function testBeforeRouteGuard(): void
    {
        $_SESSION = [];
        $app = new App();
        $app->get('/guarded', TestGuardedCtrl::class, 'secret');

        $response = $app->handle(new Request(method: 'GET', path: '/guarded'));
        $this->assertSame(401, $response->status);
    }

    public function testNamedRouteUrl(): void
    {
        $app = new App();
        $app->get('/o/{slug}', TestHomeCtrl::class, 'index', name: 'ad.show');
        $this->assertSame('/o/my-ad', $app->url('ad.show', ['slug' => 'my-ad']));
    }
}

class TestHomeCtrl extends Controller
{
    public function index(): Response { return new Response('Welcome'); }
}

class TestUserCtrl extends Controller
{
    public function show(): Response { return new Response('User ' . $this->param('id')); }
}

class TestGuardedCtrl extends Controller
{
    public function beforeRoute(): void { $this->requireAuth(); }
    public function secret(): Response { return new Response('secret'); }
}
```

```bash
vendor/bin/phpunit tests/Integration/FullCycleTest.php
git add tests/Integration/
git commit -m "test: full request cycle integration tests"
```

---

## Task 13: Session SQL Schema

**Files:**
- Create: `db/sessions.sql`

```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(128) NOT NULL PRIMARY KEY,
    data TEXT NOT NULL DEFAULT '',
    ip VARCHAR(45) NOT NULL DEFAULT '',
    agent VARCHAR(5000) NOT NULL DEFAULT '',
    stamp INT UNSIGNED NOT NULL DEFAULT 0,
    INDEX idx_stamp (stamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

```bash
git add db/
git commit -m "feat: session table schema"
```

---

## Summary

| # | Task | What goes into P1.php |
|---|------|-----------------------|
| 1 | Setup | Skeleton with namespace blocks |
| 2 | Helpers + Exception | HttpException class + h(), ha(), sGet(), mlen()... |
| 3 | Request + Response | HTTP pair |
| 4 | App | Routing + config + middleware (the core) |
| 5 | Db | PDO wrapper |
| 6 | View | Pure PHP templates |
| 7 | Session | DB handler with advisory locking |
| 8 | Csrf + Flash | Auth/UX utilities |
| 9 | Controller | Base controller |
| 10 | Utilities | Log, Validator, Cache (+rate limit), Mail |
| 11 | P1 Facade | Constants + static shortcuts |
| 12 | Integration | Tests only |
| 13 | SQL Schema | db/sessions.sql |

**Final P1.php: ~1500 lines, 15 classes, zero dependencies.**

**Usage: `require 'P1.php'` — no Composer needed.**

---

## Codex Review Notes

### Review #1 (applied)

1. **View::render() bug** — layoutFile saved to local var before nulling
2. **Route middleware** — dispatch() builds route-level middleware chain
3. **Controller hooks** — `beforeRoute()`/`afterRoute()` no args (F3 compatible)
4. **Missing helpers** — mlen, msub, sTrim, stt, sCount, sExplode added
5. **Db params** — `array|string|null` with auto-wrap
6. **Session rollback before lock** — inTransaction() check
7. **Session SQLite compat** — auto-detect driver for upsert
8. **Action-scoped CSRF nonce** — nonce() + verifyNonce()
9. **Named routes + URL generation** — url() method + P1::url()
10. **Ajax route flag** — ajax: true on routes
11. **No vendor/ in git** — .gitignore
12. **Router + Config embedded in App** — fewer classes
13. **RateLimiter merged into Cache** — rateCheck() method
14. **Single HttpException** — static factories instead of subclasses

### Review #2 (applied)

1. **stt() semantic fix** — changed from strip_tags to null-safe strtotime (brat pattern), added sStrip() for strip_tags
2. **CSRF field name** — changed from `_token` to `csrf_token` (consistent with existing projects)
3. **Session lock safety** — try/finally in write(), try/catch in read() for exception-safe lock release
4. **Header case-insensitive** — strtolower() comparison loop per RFC 7230
5. **URL encoding** — rawurlencode() on route parameters in url()
6. **Route regex safety** — preg_quote() on static parts in addRoute()
7. **Cache corrupt protection** — try/catch on unserialize, cleanup invalid files
8. **Test directory creation** — mkdir -p tests/Unit tests/Integration in Task 1

### Reviewed but not applied (conscious decisions)

- **@param route syntax** — F3-specific, migration = search&replace to {param}
- **INI config loading** — conscious decision to use PHP arrays, migration = config conversion
- **beforeRoute(\Base $f3)** — F3-specific signature, migration requires removing $f3 arg
- **Mail SMTP response validation** — acceptable risk for simple SMTP, not production mail
