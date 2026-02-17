# Worker-safe PFrame Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `resetRequestState()` to App and Db classes so PFrame can run in FrankenPHP worker mode without state leaking between requests.

**Architecture:** Two new public methods — `App::resetRequestState()` resets `$startTime`, `Db::resetRequestState()` clears query log and `$lastRowCount`. Worker entrypoint pattern documented in CLAUDE.md. Zero changes to existing FPM flow.

**Tech Stack:** PHP 8.4, PHPUnit 11, SQLite :memory: for tests

**Design doc:** `docs/plans/2026-02-17-worker-mode-design.md`

---

### Task 1: Db::resetRequestState() — test

**Files:**
- Modify: `tests/Unit/DbTest.php` (append new test method)

**Step 1: Write the failing test**

Add to `DbTest.php`:

```php
public function testResetRequestState(): void {
    $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
    $db->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
    $db->exec('INSERT INTO t (id) VALUES (?)', [1]);

    $this->assertSame(2, $db->queryCount());
    $this->assertSame(1, $db->count());

    $db->resetRequestState();

    $this->assertSame(0, $db->queryCount());
    $this->assertSame([], $db->queryLog());
    $this->assertSame(0.0, $db->queryTime());
    $this->assertSame(0, $db->count());
    $this->assertSame('', $db->log());
}
```

**Step 2: Run test to verify it fails**

Run: `vendor/bin/phpunit tests/Unit/DbTest.php --filter testResetRequestState`
Expected: FAIL — `Call to undefined method PFrame\Db::resetRequestState()`

---

### Task 2: Db::resetRequestState() — implement

**Files:**
- Modify: `src/PFrame.php` (Db class, after `log()` method ~line 951)

**Step 3: Write minimal implementation**

Add after the `log()` method in Db class:

```php
public function resetRequestState(): void {
    $this->log = [];
    $this->lastRowCount = 0;
}
```

**Step 4: Run test to verify it passes**

Run: `vendor/bin/phpunit tests/Unit/DbTest.php --filter testResetRequestState`
Expected: PASS

**Step 5: Run full DbTest suite**

Run: `vendor/bin/phpunit tests/Unit/DbTest.php`
Expected: All pass (no regressions)

**Step 6: Commit**

```bash
git add tests/Unit/DbTest.php src/PFrame.php
git commit -m "feat: add Db::resetRequestState() for worker mode"
```

---

### Task 3: App::resetRequestState() — test

**Files:**
- Modify: `tests/Unit/AppTest.php` (append new test methods)

**Step 7: Write the failing tests**

Add to `AppTest.php`:

```php
public function testResetRequestStateResetsElapsed(): void {
    $app = new App();
    usleep(10000); // 10ms
    $before = $app->elapsed();

    $app->resetRequestState();
    $after = $app->elapsed();

    $this->assertGreaterThan(0.009, $before);
    $this->assertLessThan($before, $after);
}

public function testResetRequestStatePreservesRoutes(): void {
    $app = new App();
    $app->get('/hello', HelloStub::class, 'index');
    $app->setConfig('test_key', 'test_val');

    $app->resetRequestState();

    $response = $app->handle(new Request(method: 'GET', path: '/hello'));
    $this->assertSame(200, $response->status);
    $this->assertSame('hello world', $response->body);
    $this->assertSame('test_val', $app->config('test_key'));
}

public function testResetRequestStatePreservesDb(): void {
    $app = new App();
    $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
    $db = $app->db();

    $app->resetRequestState();

    $this->assertSame($db, $app->db());
}
```

**Step 8: Run tests to verify they fail**

Run: `vendor/bin/phpunit tests/Unit/AppTest.php --filter testResetRequestState`
Expected: FAIL — `Call to undefined method PFrame\App::resetRequestState()`

---

### Task 4: App::resetRequestState() — implement

**Files:**
- Modify: `src/PFrame.php` (App class, after `instance()` method ~line 308)

**Step 9: Write minimal implementation**

Add after `instance()` method in App class:

```php
public function resetRequestState(): void {
    $this->startTime = microtime(true);
}
```

**Step 10: Run tests to verify they pass**

Run: `vendor/bin/phpunit tests/Unit/AppTest.php --filter testResetRequestState`
Expected: All 3 PASS

**Step 11: Run full test suite**

Run: `vendor/bin/phpunit`
Expected: All pass (no regressions)

**Step 12: Commit**

```bash
git add tests/Unit/AppTest.php src/PFrame.php
git commit -m "feat: add App::resetRequestState() for worker mode"
```

---

### Task 5: Integration test — worker simulation

**Files:**
- Create: `tests/Integration/WorkerModeTest.php`

**Step 13: Write integration test simulating worker loop**

```php
<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\App;
use PFrame\Controller;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class WorkerModeTest extends TestCase {
    public function testQueryLogResetsPerRequest(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db = $app->db();
        $db->exec('CREATE TABLE hits (id INTEGER PRIMARY KEY, ts TEXT)');
        $app->get('/count', CounterCtrl::class, 'index');

        // Simulate 3 worker requests — each does 1 INSERT via controller
        for ($i = 1; $i <= 3; $i++) {
            $app->resetRequestState();
            $response = $app->handle(new Request(method: 'GET', path: '/count'));
            $this->assertSame(200, $response->status);

            // Query log should reflect only THIS request's query (1 INSERT)
            $this->assertSame(1, $db->queryCount(),
                "Request $i: query log leaked from previous request");

            $db->resetRequestState();
        }

        // All 3 inserts should be in DB (persistent connection)
        $this->assertSame(3, (int) $db->var('SELECT COUNT(*) FROM hits'));
    }

    public function testTransactionDoesNotLeakBetweenRequests(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();
        $db->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)');

        // Request 1: start transaction, insert, but DON'T commit (simulate crash)
        $app->resetRequestState();
        $db->begin();
        $db->exec('INSERT INTO items (name) VALUES (?)', ['leaked']);
        // Simulate worker finally block
        if ($db->trans()) {
            $db->rollback();
        }
        $db->resetRequestState();

        // Request 2: verify no leaked data
        $app->resetRequestState();
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM items'));
        $db->resetRequestState();
    }

    public function testElapsedResetsPerRequest(): void {
        $app = new App();

        usleep(10000); // 10ms in "request 1"
        $elapsed1 = $app->elapsed();

        // Simulate worker loop: reset for "request 2"
        $app->resetRequestState();
        $elapsed2 = $app->elapsed();

        $this->assertGreaterThan(0.009, $elapsed1);
        $this->assertLessThan(0.01, $elapsed2);
    }
}

class CounterCtrl extends Controller {
    public function index(): Response {
        $db = App::instance()->db();
        $db->exec("INSERT INTO hits (ts) VALUES (?)", [date('c')]);
        return new Response(body: 'ok');
    }
}
```

**Step 14: Run integration test**

Run: `vendor/bin/phpunit tests/Integration/WorkerModeTest.php`
Expected: All 3 PASS

**Step 15: Run full test suite**

Run: `vendor/bin/phpunit`
Expected: All pass

**Step 16: Commit**

```bash
git add tests/Integration/WorkerModeTest.php
git commit -m "test: add worker mode integration tests"
```

---

### Task 6: Update CLAUDE.md documentation

**Files:**
- Modify: `CLAUDE.md` (root project docs)

**Step 17: Add worker mode section**

Add to `CLAUDE.md` after the "Bezpieczeństwo i obsługa błędów" section:

```markdown
## Worker Mode (FrankenPHP)

PFrame supports FrankenPHP worker mode via `resetRequestState()` methods:

- `App::resetRequestState()` — resets `$startTime` (elapsed timer). Routes, config, db, middleware persist.
- `Db::resetRequestState()` — clears query log and `lastRowCount`. PDO connection persists.

Worker entrypoint pattern:
```php
$handler = static function () use ($app): void {
    try {
        $app->resetRequestState();
        session_start();
        $app->run();
    } finally {
        // Guard: only cleanup DB if configured
        $dbConfig = $app->config('db');
        if (is_array($dbConfig)) {
            $db = $app->db();
            if ($db->trans()) {
                $db->rollback();
            }
            $db->resetRequestState();
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }
};

if (function_exists('frankenphp_handle_request')) {
    frankenphp_handle_request($handler);
} else {
    $handler(); // fallback: classic mode
}
```

Key rules:
- `session_start()` must be inside per-request handler, not bootstrap
- Transaction rollback in `finally` prevents tx leak between requests
- `Db::resetRequestState()` always called (not gated by `log_queries`)
```

**Step 18: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add worker mode section to CLAUDE.md"
```

---

## Summary

| Task | What | Files | Est. |
|------|------|-------|------|
| 1-2 | Db::resetRequestState() | PFrame.php, DbTest.php | 3 min |
| 3-4 | App::resetRequestState() | PFrame.php, AppTest.php | 3 min |
| 5 | Integration tests | WorkerModeTest.php | 5 min |
| 6 | Documentation | CLAUDE.md | 2 min |

Total: ~13 min, 4 commits, 2 new methods, 1 new test file.
