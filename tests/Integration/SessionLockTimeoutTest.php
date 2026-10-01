<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\App;
use PFrame\Controller;
use PFrame\Db;
use PFrame\Log;
use PFrame\Middleware;
use PFrame\Request;
use PFrame\Response;
use PFrame\Session;
use PFrame\SessionLockException;
use PHPUnit\Framework\TestCase;

/** Timeout blokady sesji na realnej ścieżce: SQLite + blokada plikowa trzymana przez „inne żądanie”. */
class SessionLockTimeoutTest extends TestCase {
    private const SID = 'locked-session-id';

    private string $dir;
    private Db $db;
    private Session $session;
    /** @var resource|null */
    private $heldLock = null;
    private array $serverSnapshot;
    private string $useCookiesSnapshot;

    protected function setUp(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        $this->serverSnapshot = $_SERVER;
        $this->useCookiesSnapshot = (string) ini_get('session.use_cookies');
        $this->dir = sys_get_temp_dir() . '/pframe_session_lock_' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/locks', 0700, true);

        $this->db = new Db(['dsn' => 'sqlite:' . $this->dir . '/sessions.sqlite']);
        $this->db->pdo()->exec((string) file_get_contents(dirname(__DIR__, 2) . '/db/sessions.sqlite.sql'));
        $this->db->exec(
            'INSERT INTO sessions (session_id, data, ip, agent, stamp) VALUES (?, ?, ?, ?, ?)',
            [self::SID, 'user_id|i:42;', '10.0.0.1', 'agent', time() - 30],
        );
        $this->useSession($this->db);
    }

    private function useSession(Db $db): void {
        $this->session = new Session($db, advisory: true, lockTimeout: 0, lockDir: $this->dir . '/locks');
        ini_set('session.use_cookies', '1');
        $this->session->register(['secure' => false]);
        ini_set('session.use_cookies', '0');
        session_id(self::SID);
    }

    protected function tearDown(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_abort();
        }
        $this->releaseHeldLock();
        session_set_save_handler(new \SessionHandler(), false);
        ini_set('session.use_cookies', $this->useCookiesSnapshot);
        $_SERVER = $this->serverSnapshot;
        foreach (glob($this->dir . '/{,locks/}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        @rmdir($this->dir . '/locks');
        @rmdir($this->dir);
    }

    private function holdLock(): void {
        $path = (string) (new \ReflectionMethod($this->session, 'fileLockPath'))->invoke($this->session, self::SID);
        $handle = fopen($path, 'c');
        $this->assertIsResource($handle);
        $this->assertTrue(flock($handle, LOCK_EX | LOCK_NB));
        $this->heldLock = $handle;
    }

    private function releaseHeldLock(): void {
        if (is_resource($this->heldLock)) {
            flock($this->heldLock, LOCK_UN);
            fclose($this->heldLock);
        }
        $this->heldLock = null;
    }

    /** @return array<string, mixed> */
    private function storedRow(): array {
        return (array) $this->db->row('SELECT data, ip, agent, stamp FROM sessions WHERE session_id = ?', [self::SID]);
    }

    private function app(): App {
        $app = new App();
        $app->get('/page', SessionLockCountingCtrl::class, 'index');
        $app->post('/form', SessionLockCountingCtrl::class, 'index', [Middleware::csrf()]);
        $app->get('/reopen-caught', SessionLockReopenCtrl::class, 'caught');
        $app->get('/reopen-uncaught', SessionLockReopenCtrl::class, 'uncaught');
        SessionLockCountingCtrl::$runs = 0;
        return $app;
    }

    public function testStartBeforeHandleDefersServiceUnavailableWithoutTouchingStoredSession(): void {
        $before = $this->storedRow();
        $this->holdLock();
        $app = $this->app();

        $this->assertFalse($app->startSession());
        $this->assertSame(PHP_SESSION_NONE, session_status());

        $response = $app->handle(new Request('POST', '/form', post: ['_csrf' => 'stale']));

        $this->assertSame(503, $response->status);
        $this->assertSame((string) SessionLockException::RETRY_AFTER_SECONDS, $response->headers['Retry-After'] ?? null);
        $this->assertStringContainsString('text/html', $response->headers['Content-Type'] ?? '');
        $this->assertStringContainsString('Serwer jest zajęty innym żądaniem tej sesji', $response->body);
        $this->assertSame(0, SessionLockCountingCtrl::$runs, 'Middleware/controller must not run on an unlocked session');
        $this->assertSame($before, $this->storedRow());

        // Odłożony błąd dotyczy tylko jednego handle().
        $this->releaseHeldLock();
        $this->assertSame(200, $app->handle(new Request('GET', '/page'))->status);
    }

    public function testAjaxAndJsonClientsGetJsonServiceUnavailable(): void {
        $this->holdLock();
        foreach ([['X-Requested-With' => 'XMLHttpRequest'], ['Accept' => 'application/json']] as $headers) {
            $app = $this->app();
            session_id(self::SID);
            $this->assertFalse($app->startSession());
            $response = $app->handle(new Request('GET', '/page', headers: $headers));

            $this->assertSame(503, $response->status);
            $this->assertSame('3', $response->headers['Retry-After'] ?? null);
            $this->assertSame('application/json', $response->headers['Content-Type'] ?? null);
            $this->assertSame(
                ['success' => false, 'message' => 'Serwer jest zajęty innym żądaniem tej sesji, spróbuj ponownie.'],
                json_decode($response->body, true, flags: JSON_THROW_ON_ERROR),
            );
        }
    }

    public function testStartSessionInsideRequestThrowsTypedException(): void {
        $before = $this->storedRow();
        $this->holdLock();
        $app = $this->app();

        $caught = $app->handle(new Request('GET', '/reopen-caught'));
        $this->assertSame(200, $caught->status);
        $this->assertSame(SessionLockException::class, $caught->body);

        session_id(self::SID);
        $uncaught = $app->handle(new Request('GET', '/reopen-uncaught'));
        $this->assertSame(503, $uncaught->status);
        $this->assertSame('3', $uncaught->headers['Retry-After'] ?? null);
        $this->assertSame(PHP_SESSION_NONE, session_status());
        $this->assertSame($before, $this->storedRow());
    }

    public function testWorkerRespondsServiceUnavailableAndTracesStatus(): void {
        $basePath = new \ReflectionProperty(Log::class, 'basePath');
        $previousBasePath = $basePath->getValue();
        $before = $this->storedRow();
        $this->holdLock();
        try {
            Log::init($this->dir);
            $app = $this->app();
            $app->setConfig('performance.trace', true);
            $app->setConfig('db', ['dsn' => 'sqlite:' . $this->dir . '/sessions.sqlite']);
            // Session na Db aplikacji, jak w produkcji: span session_lock trafia do trace żądania.
            $this->useSession($app->db());
            $_SERVER = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/page', 'REMOTE_ADDR' => '127.0.0.1'];

            ob_start();
            try {
                $app->runWorkerRequest(startSession: true);
            } finally {
                $output = (string) ob_get_clean();
            }

            $this->assertStringContainsString('Serwer jest zajęty innym żądaniem tej sesji', $output);
            $this->assertSame(0, SessionLockCountingCtrl::$runs);
            $this->assertSame($before, $this->storedRow());
            $trace = json_decode(trim((string) file_get_contents($this->dir . '/' . date('Ymd') . '_perf.jsonl')), true, flags: JSON_THROW_ON_ERROR);
            $this->assertSame(503, $trace['status']);
            $this->assertSame('session.lock', $trace['error']);
            $names = array_column($trace['events'], 'name');
            $this->assertContains('session_start', $names);
            $this->assertContains('session_lock', $names);
        } finally {
            $basePath->setValue(null, $previousBasePath);
        }
    }

    public function testFreeLockKeepsRegularSessionFlow(): void {
        $app = $this->app();

        $this->assertTrue($app->startSession());
        $this->assertSame(42, $_SESSION['user_id'] ?? null);
        $this->assertSame(200, $app->handle(new Request('GET', '/page'))->status);
        $this->assertSame(1, SessionLockCountingCtrl::$runs);
        session_write_close();
    }
}

class SessionLockCountingCtrl extends Controller {
    public static int $runs = 0;

    public function index(): Response {
        self::$runs++;
        return new Response('ok');
    }
}

class SessionLockReopenCtrl extends Controller {
    public function caught(): Response {
        try {
            App::instance()->startSession();
        } catch (SessionLockException $e) {
            return new Response($e::class);
        }
        return new Response('started');
    }

    public function uncaught(): Response {
        App::instance()->startSession();
        return new Response('started');
    }
}
