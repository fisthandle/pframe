<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\App;
use PFrame\Controller;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class WorkerModeTest extends TestCase {
    private array $serverSnapshot;
    private array $getSnapshot;
    private array $postSnapshot;
    private array $cookieSnapshot;
    private array $filesSnapshot;
    private string $sessionSavePathSnapshot;
    private string $sessionUseCookiesSnapshot;
    private string $sessionDir;

    protected function setUp(): void {
        $this->serverSnapshot = $_SERVER;
        $this->getSnapshot = $_GET;
        $this->postSnapshot = $_POST;
        $this->cookieSnapshot = $_COOKIE;
        $this->filesSnapshot = $_FILES;
        $this->sessionSavePathSnapshot = (string) ini_get('session.save_path');
        $this->sessionUseCookiesSnapshot = (string) ini_get('session.use_cookies');

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $this->sessionDir = sys_get_temp_dir() . '/pframe_worker_session_' . bin2hex(random_bytes(6));
        mkdir($this->sessionDir, 0755, true);
        ini_set('session.save_path', $this->sessionDir);
        ini_set('session.use_cookies', '0');

        $_SERVER = [];
        $_GET = [];
        $_POST = [];
        $_COOKIE = [];
        $_FILES = [];
    }

    protected function tearDown(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $_SERVER = $this->serverSnapshot;
        $_GET = $this->getSnapshot;
        $_POST = $this->postSnapshot;
        $_COOKIE = $this->cookieSnapshot;
        $_FILES = $this->filesSnapshot;

        ini_set('session.save_path', $this->sessionSavePathSnapshot);
        ini_set('session.use_cookies', $this->sessionUseCookiesSnapshot);
        foreach (glob($this->sessionDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->sessionDir);
    }

    private function primeGlobals(string $method, string $uri): void {
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['REQUEST_URI'] = $uri;
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_GET = [];
        $_POST = [];
        $_COOKIE = [];
        $_FILES = [];
    }

    public function testQueryLogResetsPerRequest(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db = $app->db();
        $db->exec('CREATE TABLE hits (id INTEGER PRIMARY KEY, ts TEXT)');
        $db->resetRequestState();

        $app->get('/count', CounterCtrl::class, 'index');

        for ($i = 1; $i <= 3; $i++) {
            $app->resetRequestState();
            $response = $app->handle(new Request(method: 'GET', path: '/count'));
            $this->assertSame(200, $response->status);
            $this->assertSame(1, $db->queryCount(), "Request $i: query log leaked from previous request");
            $db->resetRequestState();
        }

        $this->assertSame(3, (int) $db->var('SELECT COUNT(*) FROM hits'));
    }

    public function testTransactionDoesNotLeakBetweenRequests(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();
        $db->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)');

        $app->resetRequestState();
        $db->begin();
        $db->exec('INSERT INTO items (name) VALUES (?)', ['leaked']);
        if ($db->trans()) {
            $db->rollbackAll();
        }
        $db->resetRequestState();

        $app->resetRequestState();
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM items'));
        $db->resetRequestState();
    }

    public function testNestedTransactionDoesNotLeakBetweenRequests(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();
        $db->exec('CREATE TABLE nested_items (id INTEGER PRIMARY KEY, name TEXT)');

        $app->resetRequestState();
        $db->begin();
        $db->begin();
        $db->exec('INSERT INTO nested_items (name) VALUES (?)', ['leaked']);
        $db->begin();
        $db->exec('INSERT INTO nested_items (name) VALUES (?)', ['also_leaked']);
        if ($db->trans()) {
            $db->rollbackAll();
        }
        $db->resetRequestState();

        $app->resetRequestState();
        $this->assertFalse($db->trans(), 'Transaction leaked to next request');
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM nested_items'));
        $db->resetRequestState();
    }

    public function testElapsedResetsPerRequest(): void {
        $app = new App();

        usleep(10000);
        $elapsed1 = $app->elapsed();

        $app->resetRequestState();
        $elapsed2 = $app->elapsed();

        $this->assertGreaterThan(0.009, $elapsed1);
        $this->assertLessThan(0.01, $elapsed2);
    }

    public function testRunWorkerRequestRollsBackLeakedTransactionAndResetsDbState(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db = $app->db();
        $db->exec('CREATE TABLE worker_items (id INTEGER PRIMARY KEY, name TEXT)');
        $db->resetRequestState();

        $app->get('/worker-leak', WorkerLeakCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-leak');

        ob_start();
        try {
            $app->runWorkerRequest();
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertSame('leaked', $output);
        $this->assertFalse($db->trans(), 'runWorkerRequest() must not leak transactions');
        $this->assertSame(0, $db->queryCount(), 'runWorkerRequest() must reset per-request query log');
        $this->assertSame(0, $db->count(), 'runWorkerRequest() must reset per-request row count');
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM worker_items'));
    }

    public function testRunWorkerRequestRollsBackStaleTransactionBeforeStartingRequest(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();
        $db->exec('CREATE TABLE worker_counts (id INTEGER PRIMARY KEY, name TEXT)');

        $db->begin();
        $db->exec('INSERT INTO worker_counts (name) VALUES (?)', ['stale']);

        $app->get('/worker-count', WorkerCountCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-count');

        ob_start();
        try {
            $app->runWorkerRequest();
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertSame('0', $output, 'runWorkerRequest() must clear leaked transactions before request handling');
        $this->assertFalse($db->trans());
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM worker_counts'));
    }

    public function testRunWorkerRequestCanManageSessionLifecycle(): void {
        $app = new App();
        $app->get('/worker-session', WorkerSessionCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-session');

        $sessionId = bin2hex(random_bytes(8));
        session_id($sessionId);

        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertSame('session-ok', $output);
        $this->assertSame(PHP_SESSION_NONE, session_status(), 'runWorkerRequest() must close the session after the request');

        session_id($sessionId);
        $this->assertTrue(session_start());
        $this->assertSame('ok', $_SESSION['worker_test'] ?? null, 'runWorkerRequest() must persist session data before closing it');
        session_write_close();
    }

    public function testRunWorkerRequestRollsBackAndClosesSessionAfterHttpException(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();
        $db->exec('CREATE TABLE worker_http_errors (id INTEGER PRIMARY KEY, name TEXT)');

        $sessionId = bin2hex(random_bytes(8));
        session_id($sessionId);
        $app->get('/worker-http-error', WorkerHttpErrorCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-http-error');

        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertStringContainsString('Forbidden', $output);
        $this->assertFalse($db->trans(), 'runWorkerRequest() must rollback transactions after HttpException');
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM worker_http_errors'));
        $this->assertSame(PHP_SESSION_NONE, session_status(), 'runWorkerRequest() must close session after HttpException');

        session_id($sessionId);
        $this->assertTrue(session_start());
        $this->assertSame('http-error', $_SESSION['worker_http_error'] ?? null);
        session_write_close();
    }

    public function testRunWorkerRequestRollsBackAndClosesSessionAfterRuntimeException(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'debug' => 0]);
        $db = $app->db();
        $db->exec('CREATE TABLE worker_runtime_errors (id INTEGER PRIMARY KEY, name TEXT)');

        $sessionId = bin2hex(random_bytes(8));
        session_id($sessionId);
        $app->get('/worker-runtime-error', WorkerRuntimeErrorCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-runtime-error');

        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertStringContainsString('Internal Server Error', $output);
        $this->assertFalse($db->trans(), 'runWorkerRequest() must rollback transactions after runtime exception');
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM worker_runtime_errors'));
        $this->assertSame(PHP_SESSION_NONE, session_status(), 'runWorkerRequest() must close session after runtime exception');

        session_id($sessionId);
        $this->assertTrue(session_start());
        $this->assertSame('runtime-error', $_SESSION['worker_runtime_error'] ?? null);
        session_write_close();
    }
}

class CounterCtrl extends Controller {
    public function index(): Response {
        $db = App::instance()->db();
        $db->exec('INSERT INTO hits (ts) VALUES (?)', [date('c')]);
        return new Response(body: 'ok');
    }
}

class WorkerLeakCtrl extends Controller {
    public function index(): Response {
        $db = App::instance()->db();
        $db->begin();
        $db->exec('INSERT INTO worker_items (name) VALUES (?)', ['leaked']);

        return new Response(body: 'leaked');
    }
}

class WorkerSessionCtrl extends Controller {
    public function index(): Response {
        $_SESSION['worker_test'] = 'ok';

        return new Response(body: 'session-ok');
    }
}

class WorkerCountCtrl extends Controller {
    public function index(): Response {
        $db = App::instance()->db();

        return new Response(body: (string) $db->var('SELECT COUNT(*) FROM worker_counts'));
    }
}

class WorkerHttpErrorCtrl extends Controller {
    public function index(): Response {
        $_SESSION['worker_http_error'] = 'http-error';

        $db = App::instance()->db();
        $db->begin();
        $db->exec('INSERT INTO worker_http_errors (name) VALUES (?)', ['forbidden']);

        throw \PFrame\HttpException::forbidden('Worker forbidden');
    }
}

class WorkerRuntimeErrorCtrl extends Controller {
    public function index(): Response {
        $_SESSION['worker_runtime_error'] = 'runtime-error';

        $db = App::instance()->db();
        $db->begin();
        $db->exec('INSERT INTO worker_runtime_errors (name) VALUES (?)', ['boom']);

        throw new \RuntimeException('worker boom');
    }
}
