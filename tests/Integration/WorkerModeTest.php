<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\App;
use PFrame\Controller;
use PFrame\Db;
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

    public function testRunWorkerRequestRollsBackNestedTransactionsAndResetsDbState(): void {
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

        $this->assertSame('nested-leak', $output);
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

    public function testRunWorkerRequestDoesNotDispatchWhenSessionStartFails(): void {
        $app = new App();
        $app->get('/must-not-run', WorkerMustNotRunCtrl::class, 'index');
        $this->primeGlobals('GET', '/must-not-run');
        WorkerMustNotRunCtrl::$runs = 0;
        ini_set('session.save_path', '/proc/pframe-session-start-failure-' . bin2hex(random_bytes(6)));

        set_error_handler(static fn(): bool => true);
        $error = null;
        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
        } catch (\RuntimeException $e) {
            $error = $e;
        } finally {
            $output = (string) ob_get_clean();
            restore_error_handler();
        }

        $this->assertInstanceOf(\RuntimeException::class, $error);
        $this->assertSame('Failed to start worker session.', $error->getMessage());
        $this->assertSame(0, WorkerMustNotRunCtrl::$runs, 'Controller must not run without an active session');
        $this->assertSame('', $output);
        $this->assertSame(PHP_SESSION_NONE, session_status());
    }

    public function testRunWorkerRequestClosesSessionWhenRollbackCleanupThrows(): void {
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['trans', 'rollbackAll', 'resetRequestState'])
            ->getMock();
        $db->method('trans')->willReturnOnConsecutiveCalls(false, true);
        $db->expects($this->once())
            ->method('rollbackAll')
            ->willThrowException(new \RuntimeException('cleanup rollback failed'));

        $app = new App();
        $app->setDb($db);
        $app->get('/cleanup-error', WorkerNoopCtrl::class, 'index');
        $this->primeGlobals('GET', '/cleanup-error');
        session_id(bin2hex(random_bytes(8)));

        $error = null;
        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
        } catch (\RuntimeException $e) {
            $error = $e;
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertSame('cleanup-ok', $output);
        $this->assertInstanceOf(\RuntimeException::class, $error);
        $this->assertSame('cleanup rollback failed', $error->getMessage());
        $this->assertSame(PHP_SESSION_NONE, session_status(), 'Session must close even when database cleanup fails');
    }

    public function testRunWorkerRequestCanManageSessionLifecycle(): void {
        $app = new App();
        $app->get('/worker-session', WorkerSessionCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-session');
        $app->performance()->record('stale', 1.0);

        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
        } finally {
            $output = (string) ob_get_clean();
        }

        $this->assertSame('session-ok', $output);
        $this->assertSame(PHP_SESSION_NONE, session_status(), 'runWorkerRequest() must close the session after the request');
        $spans = $app->performance()->snapshot()['spans'];
        $this->assertArrayHasKey('session_start', $spans);
        $this->assertSame(1, $spans['session_start']['count']);
        $this->assertArrayNotHasKey('stale', $spans, 'Worker request must reset profiler state before dispatch');

        $this->assertTrue(session_start());
        $this->assertSame('ok', $_SESSION['worker_test'] ?? null, 'runWorkerRequest() must persist session data before closing it');
        session_write_close();
    }

    public function testWorkerResetsDiagnosticsAfterDatabaseSessionIsSaved(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db = $app->db();
        $db->pdo()->exec((string) file_get_contents(dirname(__DIR__, 2) . '/db/sessions.sqlite.sql'));
        session_set_save_handler(new \PFrame\Session($db, advisory: false), false);
        session_id(bin2hex(random_bytes(8)));
        $app->get('/worker-session', WorkerSessionCtrl::class, 'index');
        $this->primeGlobals('GET', '/worker-session');

        ob_start();
        try {
            $app->runWorkerRequest(startSession: true);
            $this->assertSame(0, $db->totalQueryCount());
            $this->assertSame(0, $db->queryCount());
            $this->assertSame(0, $db->count());
            $this->assertSame(1, $db->var('SELECT COUNT(*) FROM sessions'));
        } finally {
            ob_end_clean();
            session_set_save_handler(new \SessionHandler(), false);
        }
    }

    public function testRunWorkerRequestRollsBackAndClosesSessionAfterHttpException(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();
        $db->exec('CREATE TABLE worker_http_errors (id INTEGER PRIMARY KEY, name TEXT)');

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

        $this->assertTrue(session_start());
        $this->assertSame('http-error', $_SESSION['worker_http_error'] ?? null);
        session_write_close();
    }

    public function testRunWorkerRequestRollsBackAndClosesSessionAfterRuntimeException(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'debug' => 0]);
        $db = $app->db();
        $db->exec('CREATE TABLE worker_runtime_errors (id INTEGER PRIMARY KEY, name TEXT)');

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

        $this->assertTrue(session_start());
        $this->assertSame('runtime-error', $_SESSION['worker_runtime_error'] ?? null);
        session_write_close();
    }
}

class WorkerLeakCtrl extends Controller {
    public function index(): Response {
        $db = App::instance()->db();
        $db->begin();
        $db->exec('INSERT INTO worker_items (name) VALUES (?)', ['outer']);
        $db->begin();
        $db->exec('INSERT INTO worker_items (name) VALUES (?)', ['nested']);
        $db->begin();
        $db->exec('INSERT INTO worker_items (name) VALUES (?)', ['deeply-nested']);

        return new Response(body: 'nested-leak');
    }
}

class WorkerMustNotRunCtrl extends Controller {
    public static int $runs = 0;

    public function index(): Response {
        self::$runs++;
        return new Response(body: 'unexpected');
    }
}

class WorkerNoopCtrl extends Controller {
    public function index(): Response {
        return new Response(body: 'cleanup-ok');
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
