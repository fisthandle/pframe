# Design: Worker-safe PFrame

**Status:** Approved
**Date:** 2026-02-17
**Approach:** A (Minimal) — two new methods in PFrame.php, zero changes to existing flow

## Goal

Make PFrame worker-mode compatible for FrankenPHP without breaking FPM deployment.

## Context

- PFrame.php: single-file PHP 8.4+ micro-framework (~1800 LOC)
- Currently: FrankenPHP classic mode (FPM-like) + opcache + preloading
- Worker mode: PHP process stays alive, reuses bootstrap between requests
- Expected gain: ~2-8ms per request (persistent DB connection = main benefit)

## Changes in src/PFrame.php

### 1. App::resetRequestState()

```php
public function resetRequestState(): void {
    $this->startTime = microtime(true);
}
```

Resets per-request mutable state. Preserves: routes, config, db, middleware, error handlers.

Only `$startTime` needs reset — all other App properties are bootstrap config.

### 2. Db::resetRequestState()

```php
public function resetRequestState(): void {
    $this->log = [];
    $this->lastRowCount = 0;
}
```

Prevents unbounded `$log` growth and stale `lastRowCount` across requests.
Called unconditionally (not gated by `log_queries`), because `lastRowCount` is always used.

### What we do NOT change

- **Log static state** — config, set once at bootstrap
- **Flash** — per-use instantiation, no singleton
- **Session/Csrf** — superglobal-based, FrankenPHP resets superglobals
- **Shutdown handler** — guard `$shutdownRegistered` works correctly
- **Db connection** — persistent = whole point of worker mode

## Worker entrypoint pattern (docs only)

```php
<?php
// Bootstrap once (project-specific)
require __DIR__ . '/../vendor/autoload.php';
$app = \PFrame\App::instance();
$app->loadConfig(__DIR__ . '/../config/app.php');
// ... register routes ...

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
    $handler();
}
```

Key points:
- `session_start()` in per-request handler, not bootstrap
- Transaction rollback in `finally` prevents tx leak between requests
- `Db::resetRequestState()` always called (not gated by log_queries)
- Fallback to classic mode when not running as worker

## Tests

1. `App::resetRequestState()` resets `startTime`, preserves routes/config/db
2. `Db::resetRequestState()` clears log and lastRowCount
3. Integration: verify multiple "requests" on same App instance don't leak state

## Risk

MEDIUM — Two new methods, zero changes to existing flow. FPM unaffected.
Edge cases (tx leak, session lifecycle, stale count) addressed in worker pattern.

## Codex Review

Codex found 3 major gaps in initial design (tx leak, lastRowCount leak, session lifecycle).
All addressed in this revision.
