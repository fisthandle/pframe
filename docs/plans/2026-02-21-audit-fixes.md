# PFrame Audit Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 3 critical, 7 major, and 5 quick-win findings from the full audit of PFrame.php.

**Architecture:** All changes in single file `src/PFrame.php` + corresponding test additions. No API breaking changes. Each fix is independent — can be committed separately.

**Tech Stack:** PHP 8.4, PHPUnit, PHPStan level 8

**Scope exclusions:** Minor simplification-only findings (cosmetic DRY, dead code guards) — separate PR later. Session advisory lock silent data loss (Critical #2) — needs design decision, tracked as TODO.

---

### Task 1: Fix OB leak in View::renderFile() [Critical]

Template exception leaves `ob_start()` open. In worker mode this nests per request → OOM.

**Files:**
- Modify: `src/PFrame.php:1396` (View::renderFile)
- Test: `tests/Unit/ViewTest.php`

**Step 1: Write the failing test**

Add to `tests/Unit/ViewTest.php`:

```php
public function testRenderFileExceptionCleansOutputBuffer(): void {
    $dir = sys_get_temp_dir() . '/pframe_view_test_' . mt_rand();
    mkdir($dir);
    file_put_contents($dir . '/throw.php', '<?php throw new \RuntimeException("boom");');

    $view = new \PFrame\View($dir);
    $levelBefore = ob_get_level();

    try {
        $view->render('throw.php');
        $this->fail('Expected RuntimeException');
    } catch (\RuntimeException) {
        // expected
    }

    $this->assertSame($levelBefore, ob_get_level(), 'OB level must be restored after exception');

    unlink($dir . '/throw.php');
    rmdir($dir);
}
```

**Step 2: Run test to verify it fails**

Run: `php vendor/bin/phpunit tests/Unit/ViewTest.php --filter=testRenderFileExceptionCleansOutputBuffer -v`
Expected: FAIL — OB level is levelBefore + 1

**Step 3: Implement the fix**

In `src/PFrame.php`, View::renderFile() around line 1396, change:

```php
// BEFORE:
$t = microtime(true);
ob_start();
include $filePath;
$result = (string) ob_get_clean();
$this->renderLog[] = ['template' => $template, 'ms' => round((microtime(true) - $t) * 1000, 2)];
return $result;

// AFTER:
$t = microtime(true);
ob_start();
try {
    include $filePath;
} catch (\Throwable $e) {
    ob_end_clean();
    throw $e;
}
$result = (string) ob_get_clean();
$this->renderLog[] = ['template' => $template, 'ms' => round((microtime(true) - $t) * 1000, 2)];
return $result;
```

**Step 4: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/ViewTest.php -v`
Expected: ALL PASS

**Step 5: Run full suite + PHPStan**

Run: `php vendor/bin/phpunit && php vendor/bin/phpstan analyse --no-progress`
Expected: ALL PASS, no errors

**Step 6: Commit**

```bash
git add src/PFrame.php tests/Unit/ViewTest.php
git commit -m "fix: clean output buffer on template exception (worker mode OB leak)"
```

---

### Task 2: Fix validateCsrf array crash [Critical]

`Controller::validateCsrf()` passes `mixed` to `?string` — array CSRF token → 500 instead of 403.

**Files:**
- Modify: `src/PFrame.php:1781` (Controller::validateCsrf)
- Test: `tests/Unit/AppTest.php`

**Step 1: Write the failing integration test**

The bug is in `Controller::validateCsrf` which passes raw POST value (could be array) to `Csrf::validate(?string)`. Test through the App routing layer. Add to `tests/Unit/AppTest.php`:

```php
public function testCsrfArrayTokenReturns403Not500(): void {
    $app = new App();
    $app->post('/csrf-test', [CsrfTestCtrl::class, 'run']);
    $app->use(\PFrame\Middleware::csrf());

    $_SESSION[Csrf::SESSION_KEY] = 'valid-token';
    $request = new Request('POST', '/csrf-test', [], [Csrf::FIELD_NAME => ['array', 'value']]);
    $response = $app->handle($request);

    $this->assertSame(403, $response->statusCode);
}
```

Add test controller at the bottom of the test file (alongside existing test controllers):

```php
class CsrfTestCtrl {
    public function run(): Response {
        return new Response('ok');
    }
}
```

**Step 2: Run test to verify it fails**

Run: `php vendor/bin/phpunit tests/Unit/AppTest.php --filter=testCsrfArrayTokenReturns403Not500 -v`
Expected: FAIL — TypeError (passing array to ?string)

**Step 3: Implement the fix**

In `src/PFrame.php:1781`, change:

```php
// BEFORE:
$token = $this->request->post(Csrf::FIELD_NAME) ?? $this->request->header('X-Csrf-Token');
if (!Csrf::validate($token)) {

// AFTER:
$raw = $this->request->post(Csrf::FIELD_NAME) ?? $this->request->header('X-Csrf-Token');
$token = is_scalar($raw) ? (string) $raw : null;
if (!Csrf::validate($token)) {
```

**Step 4: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/AppTest.php -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/PFrame.php tests/Unit/AppTest.php
git commit -m "fix: reject non-string CSRF tokens in Controller::validateCsrf (500→403)"
```

---

### Task 3: Sanitize batchInsert identifiers [Major/Security]

`$table`, `$columns`, `$mode` concatenated directly into SQL.

**Files:**
- Modify: `src/PFrame.php:1121` (Db::batchInsert)
- Test: `tests/Unit/DbTest.php`

**Step 1: Write the failing test**

Add to `tests/Unit/DbTest.php`:

```php
public function testBatchInsertRejectsInvalidMode(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->db->batchInsert('users', ['name'], [['Joe']], 'DROP TABLE users; --');
}

public function testBatchInsertQuotesIdentifiers(): void {
    $this->db->exec('CREATE TABLE "odd table" (col1 TEXT)');
    $this->db->batchInsert('odd table', ['col1'], [['val']]);
    $this->assertSame('val', $this->db->var('SELECT col1 FROM "odd table"'));
}
```

**Step 2: Run tests to verify they fail**

Run: `php vendor/bin/phpunit tests/Unit/DbTest.php --filter="testBatchInsert" -v`
Expected: FAIL — no exception for invalid mode, no quoting

**Step 3: Implement the fix**

In `src/PFrame.php`, Db::batchInsert() around line 1121:

Add at the top of the method:

```php
$allowedModes = ['INSERT', 'REPLACE', 'INSERT OR REPLACE', 'INSERT OR IGNORE', 'INSERT IGNORE'];
if (!in_array(strtoupper($mode), $allowedModes, true)) {
    throw new \InvalidArgumentException('Invalid insert mode: ' . $mode);
}
$mode = strtoupper($mode);

$quoteId = static fn(string $id): string => '`' . str_replace('`', '``', $id) . '`';
$colList = implode(', ', array_map($quoteId, $columns));
$quotedTable = $quoteId($table);
```

Then use `$quotedTable` and `$colList` in the SQL string instead of raw `$table` / `implode(', ', $columns)`.

**Step 4: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/DbTest.php -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/PFrame.php tests/Unit/DbTest.php
git commit -m "fix: sanitize batchInsert identifiers and allowlist mode (SQLi prevention)"
```

---

### Task 4: Fix open redirect when HTTP_HOST is empty [Major/Security]

`Response::redirect()` skips host check when `HTTP_HOST` is absent.

**Files:**
- Modify: `src/PFrame.php:256` (Response::redirect)
- Test: `tests/Unit/ResponseTest.php`

**Step 1: Write the failing test**

Add to `tests/Unit/ResponseTest.php`:

```php
public function testRedirectBlocksExternalUrlWithoutHost(): void {
    unset($_SERVER['HTTP_HOST']);
    $this->expectException(\InvalidArgumentException::class);
    \PFrame\Response::redirect('https://evil.com/phish');
}
```

Note: `testRedirectAllowsRelativePath` already exists in ResponseTest — no need for a duplicate.

**Step 2: Run test to verify it fails**

Run: `php vendor/bin/phpunit tests/Unit/ResponseTest.php --filter="testRedirectBlocksExternalUrlWithoutHost" -v`
Expected: FAIL — no exception thrown

**Step 3: Implement the fix**

In `src/PFrame.php:261-270`, the actual code is:

```php
// BEFORE:
if (!str_starts_with($url, '/')) {
    $host = parse_url($url, PHP_URL_HOST);
    $currentHost = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if (is_string($host) && $currentHost !== '') {
        $normalizedCurrentHost = (string) (parse_url('http://' . $currentHost, PHP_URL_HOST) ?? $currentHost);
        if (strcasecmp($host, $normalizedCurrentHost) !== 0) {
            throw new \InvalidArgumentException('External redirect not allowed: ' . $url);
        }
    }
}

// AFTER:
if (!str_starts_with($url, '/')) {
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
```

Key change: when URL has a host but `$currentHost` is empty → block (not skip). Preserves existing port-normalization logic.

**Step 4: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/ResponseTest.php -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/PFrame.php tests/Unit/ResponseTest.php
git commit -m "fix: block external redirects when HTTP_HOST is empty"
```

---

### Task 5: Validate Log::toFile filename [Major/Security]

Path traversal via `../` in `$filename`.

**Files:**
- Modify: `src/PFrame.php:1869` (Log::toFile)
- Test: `tests/Unit/LogTest.php`

**Step 1: Write the failing test**

Add to `tests/Unit/LogTest.php`:

```php
public function testToFileRejectsPathTraversal(): void {
    $this->expectException(\InvalidArgumentException::class);
    \PFrame\Log::init(sys_get_temp_dir());
    \PFrame\Log::toFile('../../etc/evil.log', 'pwned');
}

public function testToFileRejectsBackslash(): void {
    $this->expectException(\InvalidArgumentException::class);
    \PFrame\Log::init(sys_get_temp_dir());
    \PFrame\Log::toFile('..\evil.log', 'pwned');
}
```

**Step 2: Run tests to verify they fail**

Expected: FAIL — no exception

**Step 3: Implement the fix**

At the top of `Log::toFile()`:

```php
if (str_contains($filename, '/') || str_contains($filename, '\\') || str_contains($filename, "\0")) {
    throw new \InvalidArgumentException('Invalid log filename: ' . $filename);
}
```

**Step 4: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/LogTest.php -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/PFrame.php tests/Unit/LogTest.php
git commit -m "fix: reject path traversal in Log::toFile filename"
```

---

### Task 6: Cache realpath in View constructor [Performance]

`realpath($this->basePath)` called per renderFile() — syscall per partial.

**Files:**
- Modify: `src/PFrame.php:1344` (View class)

**Step 1: Implement**

```php
// BEFORE:
public function __construct(private readonly string $basePath) {
}

// AFTER:
private readonly string $realBasePath;

public function __construct(private readonly string $basePath) {
    $resolved = realpath($basePath);
    if ($resolved === false) {
        throw new \RuntimeException('View base path not found: ' . $basePath);
    }
    $this->realBasePath = $resolved;
}
```

In `renderFile()`, replace:
```php
$realBase = realpath($this->basePath);
```
with:
```php
$realBase = $this->realBasePath;
```

And remove the `$realBase === false` check (it's guaranteed non-false now).

**Step 2: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/ViewTest.php -v`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add src/PFrame.php
git commit -m "perf: cache realpath in View constructor (eliminate syscall per partial)"
```

---

### Task 7: Cache PDO driver name in Db [Performance]

`PDO::getAttribute(ATTR_DRIVER_NAME)` called on every session write and batchInsert.

**Files:**
- Modify: `src/PFrame.php:999` (Db constructor), `src/PFrame.php:1121` (batchInsert), `src/PFrame.php:1482` (Session::write)

**Step 1: Implement in Db**

Add property and set in constructor:

```php
private readonly string $driver;

// In constructor, after $this->pdo = new \PDO(...):
$this->driver = (string) $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
```

Add public getter:
```php
public function driver(): string {
    return $this->driver;
}
```

In `batchInsert()`, replace `$this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)` with `$this->driver`.

**Step 2: Implement in Session**

In `Session::write()`, replace:
```php
$driver = (string) $this->db->pdo()->getAttribute(\PDO::ATTR_DRIVER_NAME);
```
with:
```php
$driver = $this->db->driver();
```

Also cache in `Session::__construct` for `useAdvisoryLock`:
```php
$this->useAdvisoryLock = $this->advisory && $this->db->driver() === 'mysql';
```

**Step 3: Run tests**

Run: `php vendor/bin/phpunit -v`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add src/PFrame.php
git commit -m "perf: cache PDO driver name in Db constructor"
```

---

### Task 8: O(1) header lookup in Request [Performance]

`Request::header()` does O(n) scan. Headers already normalized in parseServerHeaders.

**Files:**
- Modify: `src/PFrame.php:63-75` (Request constructor)
- Modify: `src/PFrame.php:179` (Request::header)
- Test: `tests/Unit/RequestTest.php`

**Step 1: Write test for non-normalized headers**

Add to `tests/Unit/RequestTest.php`:

```php
public function testHeaderLookupCaseInsensitiveWithManualHeaders(): void {
    $request = new Request('GET', '/', headers: ['x-custom-header' => 'value']);
    $this->assertSame('value', $request->header('X-Custom-Header'));
    $this->assertSame('value', $request->header('x-custom-header'));
}
```

**Step 2: Run test to verify it passes (baseline)**

Run: `php vendor/bin/phpunit tests/Unit/RequestTest.php --filter=testHeaderLookupCaseInsensitiveWithManualHeaders -v`
Expected: PASS (current O(n) scan handles this)

**Step 3: Implement header normalization in constructor**

The `$headers` property uses `public readonly` promoted parameter, so it cannot be reassigned. Change to regular property:

In `src/PFrame.php:63-75`, change:

```php
// BEFORE:
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

// AFTER:
/** @var array<string, string> */
public readonly array $headers;

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
```

**Step 4: Implement O(1) lookup**

In `src/PFrame.php:179`, change:

```php
// BEFORE:
public function header(string $name, ?string $default = null): ?string {
    $needle = strtolower($name);
    foreach ($this->headers as $key => $value) {
        if (strtolower((string) $key) === $needle) {
            return (string) $value;
        }
    }
    return $default;
}

// AFTER:
public function header(string $name, ?string $default = null): ?string {
    return $this->headers[ucwords(strtolower($name), '-')] ?? $default;
}
```

**Step 5: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/RequestTest.php -v`
Expected: ALL PASS (including baseline test from Step 1)

Run: `php vendor/bin/phpunit -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add src/PFrame.php tests/Unit/RequestTest.php
git commit -m "perf: O(1) header lookup with normalized keys in Request"
```

---

### Task 9: Eliminate double parseServerHeaders call [Performance]

`fromGlobalsWithProxies` parses headers then `buildFromGlobals` parses again.

**Files:**
- Modify: `src/PFrame.php:83-90` (Request::fromGlobalsWithProxies, buildFromGlobals)

**Step 1: Implement**

Add optional `$headers` parameter to `buildFromGlobals`:

```php
// BEFORE:
private static function buildFromGlobals(string $ip): static {
    // ...
    $headers = self::parseServerHeaders($_SERVER);

// AFTER:
private static function buildFromGlobals(string $ip, ?array $headers = null): static {
    // ...
    $headers ??= self::parseServerHeaders($_SERVER);
```

In `fromGlobalsWithProxies()`, pass the already-parsed headers:

```php
public static function fromGlobalsWithProxies(array $trustedProxies = []): static {
    $headers = self::parseServerHeaders($_SERVER);
    return self::buildFromGlobals(self::resolveIp($_SERVER, $headers, $trustedProxies), $headers);
}
```

**Step 2: Run tests**

Run: `php vendor/bin/phpunit tests/Unit/RequestTest.php -v`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add src/PFrame.php
git commit -m "perf: eliminate double parseServerHeaders in fromGlobalsWithProxies"
```

---

### Task 10: Optimize 405 detection [Performance]

405 scan iterates ALL routes with regex. Use routesByMethod + early break.

**Files:**
- Modify: `src/PFrame.php:684` (App::handle, 405 detection block)

**Step 1: Implement**

```php
// BEFORE:
$allowed = [];
foreach ($this->routes as $route) {
    if ($route['ajax'] && !$isAjax) { continue; }
    if (preg_match($route['regex'], $path)) {
        foreach ($route['methods'] as $m) {
            $allowed[strtoupper($m)] = true;
        }
    }
}

// AFTER:
$allowed = [];
foreach ($this->routesByMethod as $httpMethod => $indexes) {
    if ($httpMethod === $method) {
        continue;
    }
    foreach ($indexes as $i) {
        $route = $this->routes[$i];
        if ($route['ajax'] && !$isAjax) {
            continue;
        }
        if (preg_match($route['regex'], $path)) {
            $allowed[$httpMethod] = true;
            break;
        }
    }
}
```

**Step 2: Run tests**

Run: `php vendor/bin/phpunit -v`
Expected: ALL PASS (existing 405 tests cover this)

**Step 3: Commit**

```bash
git add src/PFrame.php
git commit -m "perf: optimize 405 detection with routesByMethod index"
```

---

### Task 11: Remove double instanceof in App::instance() [Quality]

Second `instanceof` check silently replaces configured App with blank instance.

**Files:**
- Modify: `src/PFrame.php:377` (App::instance)

**Step 1: Implement**

```php
// BEFORE:
public static function instance(): static {
    if (self::$instance === null) {
        self::$instance = new static();
    }
    if (!self::$instance instanceof static) {
        self::$instance = new static();
    }
    return self::$instance;
}

// AFTER:
public static function instance(): static {
    if (self::$instance === null) {
        self::$instance = new static();
    }
    return self::$instance;
}
```

**Step 2: Run tests**

Run: `php vendor/bin/phpunit -v`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add src/PFrame.php
git commit -m "fix: remove silent App instance replacement in App::instance()"
```

---

### Task 12: Final verification

**Step 1:** Run full test suite:
```bash
php vendor/bin/phpunit -v
```
Expected: ALL PASS (293+ tests)

**Step 2:** Run PHPStan:
```bash
php vendor/bin/phpstan analyse --no-progress
```
Expected: 0 errors

**Step 3:** Copy to domownik and test:
```bash
cp src/PFrame.php ~/dev/domownik/lib/PFrame.php
cd ~/dev/domownik && php vendor/bin/phpunit --testsuite Unit -v
```
Expected: ALL PASS

---

## Deferred Items (separate PR)

- **Critical #2 (Session advisory lock data loss):** Needs design decision — fallback-write vs throw. Track in TODO.
- **Db::resetRequestState() savepoint drain:** Related to worker mode — needs integration test with real nested transactions.
- **Minor simplifications:** stripLeadingComments merge, dead code guards, GLOB_BRACE, etc.
