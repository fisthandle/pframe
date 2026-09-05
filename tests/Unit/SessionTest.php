<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Db;
use PFrame\Session;
use PHPUnit\Framework\TestCase;

class SessionTest extends TestCase {
    private Db $db;
    private array $serverSnapshot;

    protected function setUp(): void {
        $this->serverSnapshot = $_SERVER;
        $_SERVER = [];
        $this->db = new Db(['dsn' => 'sqlite::memory:']);
        $this->db->exec('CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY,
            data TEXT NOT NULL DEFAULT "",
            ip TEXT NOT NULL DEFAULT "",
            agent TEXT NOT NULL DEFAULT "",
            stamp INTEGER NOT NULL DEFAULT 0
        )');
    }

    protected function tearDown(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        session_set_save_handler(new \SessionHandler(), true);
        $_SERVER = $this->serverSnapshot;
    }

    public function testWriteAndRead(): void {
        $session = new Session($this->db, advisory: false);
        $session->write('sid1', 'test_data');
        $this->assertSame('test_data', $session->read('sid1'));
    }

    public function testReadMissing(): void {
        $session = new Session($this->db, advisory: false);
        $this->assertSame('', $session->read('nonexistent'));
    }

    public function testDestroy(): void {
        $session = new Session($this->db, advisory: false);
        $session->write('sid1', 'data');
        $session->destroy('sid1');
        $this->assertSame('', $session->read('sid1'));
    }

    public function testGc(): void {
        $session = new Session($this->db, advisory: false);
        $this->db->exec(
            'INSERT INTO sessions (session_id, data, stamp) VALUES (?, ?, ?)',
            ['old', 'data', time() - 7200],
        );
        $session->write('new', 'data');

        $cleaned = $session->gc(3600);
        $this->assertSame(1, $cleaned);
        $this->assertSame('data', $session->read('new'));
    }

    public function testAdvisoryModeOnSqliteStillWorks(): void {
        $session = new Session($this->db, advisory: true);
        $session->open('', 'PHPSESSID');
        $session->write('sid1', 'x');
        $this->assertSame('x', $session->read('sid1'));
        $this->assertTrue($session->close());
    }

    public function testRegisterAndGcReturnType(): void {
        $session = new Session($this->db, advisory: false);
        $session->register();
        $this->assertTrue(session_get_cookie_params()['secure']);
        $this->assertIsInt($session->gc(0));
    }

    public function testRegisterAllowsOverridingSecureCookieFlag(): void {
        $session = new Session($this->db, advisory: false);
        $session->register(['secure' => false]);
        $this->assertFalse(session_get_cookie_params()['secure']);
    }

    public function testRegisterNormalizesNullableCookiePathAndDomain(): void {
        $session = new Session($this->db, advisory: false);
        $session->register(['secure' => false]);
        $defaultCookieParams = session_get_cookie_params();
        $this->assertSame('/', $defaultCookieParams['path']);
        $this->assertSame('', $defaultCookieParams['domain']);

        $session->register([
            'path' => null,
            'domain' => null,
            'secure' => false,
        ]);

        $cookieParams = session_get_cookie_params();
        $this->assertSame('', $cookieParams['path']);
        $this->assertSame('', $cookieParams['domain']);
    }

    public function testRegisterLifetimeZeroPreservesGcMaxlifetime(): void {
        $previous = ini_get('session.gc_maxlifetime');
        ini_set('session.gc_maxlifetime', '4321');

        try {
            $session = new Session($this->db, advisory: false);
            $session->register(['lifetime' => 0, 'secure' => false]);

            $this->assertSame('4321', ini_get('session.gc_maxlifetime'));
            $this->assertSame(0, session_get_cookie_params()['lifetime']);

            $session->register(['lifetime' => 1234, 'secure' => false]);
            $this->assertSame('1234', ini_get('session.gc_maxlifetime'));
            $this->assertSame(1234, session_get_cookie_params()['lifetime']);
        } finally {
            if (is_string($previous)) {
                ini_set('session.gc_maxlifetime', $previous);
            }
        }
    }

    public function testStrictModeRejectsUnknownSuppliedSessionId(): void {
        $unknownId = str_repeat('A', 64);
        $session = new Session($this->db, advisory: false);
        $session->register(['secure' => false]);
        session_id($unknownId);

        $this->assertTrue(session_start());
        $this->assertNotSame($unknownId, session_id());
    }

    public function testValidateIdAcceptsOnlyPersistedSession(): void {
        $session = new Session($this->db, advisory: false);
        $session->write('known-session', 'payload');

        $this->assertTrue($session->validateId('known-session'));
        $this->assertFalse($session->validateId('unknown-session'));
    }

    public function testReadAndValidateIdRejectExpiredRowsWithoutGc(): void {
        $previous = ini_get('session.gc_maxlifetime');
        ini_set('session.gc_maxlifetime', '60');
        $now = time();
        $this->db->exec(
            'INSERT INTO sessions (session_id, data, stamp) VALUES (?, ?, ?), (?, ?, ?)',
            ['expired-session', 'expired', 1, 'fresh-session', 'fresh', $now],
        );

        try {
            $session = new Session($this->db, advisory: false);

            $this->assertSame('', $session->read('expired-session'));
            $this->assertSame('expired', $this->db->var(
                'SELECT data FROM sessions WHERE session_id = ?',
                ['expired-session'],
            ));
            $this->assertFalse($session->validateId('expired-session'));
            $this->assertSame('fresh', $session->read('fresh-session'));
            $this->assertTrue($session->validateId('fresh-session'));
        } finally {
            if (is_string($previous)) {
                ini_set('session.gc_maxlifetime', $previous);
            }
        }
    }

    public function testSessionWriteWorksWithAdvisoryDisabled(): void {
        $session = new Session($this->db, advisory: false);
        $id = bin2hex(random_bytes(16));

        $session->write($id, serialize(['test' => 'data']));
        $data = $session->read($id);

        $this->assertStringContainsString('test', $data);
    }

    public function testWriteUsesMysqlUpsertQueryWhenDriverIsMysql(): void {
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'exec'])
            ->getMock();
        $db->method('driver')->willReturn('mysql');
        $db->expects($this->once())
            ->method('exec')
            ->with(
                $this->stringContains('ON DUPLICATE KEY UPDATE'),
                $this->callback(static function (array $params): bool {
                    return $params[0] === 'sid_mysql' && $params[1] === 'payload';
                }),
            )
            ->willReturn(1);

        $session = new Session($db, advisory: false);
        $this->assertTrue($session->write('sid_mysql', 'payload'));
    }

    public function testWriteSkipsFullInsertWhenDataUnchanged(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db->pdo()->exec('CREATE TABLE sessions (session_id TEXT PRIMARY KEY, data TEXT, ip TEXT, agent TEXT, stamp INTEGER)');

        $session = new Session($db, advisory: false);
        $session->open('', '');
        $session->read('test-lazy');
        $session->write('test-lazy', 'data|s:5:"hello";');

        $db->resetRequestState();
        $session->read('test-lazy');
        $session->write('test-lazy', 'data|s:5:"hello";');

        $log = $db->queryLog();
        $lastQuery = end($log);
        $this->assertIsArray($lastQuery);
        $this->assertStringContainsString('UPDATE', $lastQuery['sql'], 'Unchanged data should only UPDATE stamp');
    }

    public function testWriteRefreshesStampWhenDataUnchanged(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db->pdo()->exec('CREATE TABLE sessions (session_id TEXT PRIMARY KEY, data TEXT, ip TEXT, agent TEXT, stamp INTEGER)');

        $session = new Session($db, advisory: false);
        $session->open('', '');
        $session->read('test-stamp');
        $session->write('test-stamp', 'data|s:5:"hello";');

        $db->exec('UPDATE sessions SET stamp = ? WHERE session_id = ?', [1000, 'test-stamp']);

        $db->resetRequestState();
        $session->read('test-stamp');
        $session->write('test-stamp', 'data|s:5:"hello";');

        $row = $db->row('SELECT stamp FROM sessions WHERE session_id = ?', ['test-stamp']);
        $this->assertNotNull($row);
        $this->assertGreaterThan(1000, (int) $row['stamp'], 'Stamp should be refreshed even when data unchanged');
    }

    public function testMysqlZeroUpdateDoesNotPersistWhenSessionRowExists(): void {
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'exec', 'var'])
            ->getMock();
        $db->method('driver')->willReturn('mysql');
        $db->expects($this->once())
            ->method('exec')
            ->with(
                'UPDATE sessions SET stamp = ? WHERE session_id = ?',
                $this->callback(static fn(array $params): bool => $params[1] === 'same-second'),
            )
            ->willReturn(0);
        $db->method('var')->willReturnCallback(
            static function (string $sql): mixed {
                if ($sql === 'SELECT data FROM sessions WHERE session_id = ? AND stamp >= ?') {
                    return 'payload';
                }
                if ($sql === 'SELECT 1 FROM sessions WHERE session_id = ?') {
                    return 1;
                }

                return null;
            },
        );

        $session = new Session($db, advisory: false);
        $session->open('', '');
        $this->assertSame('payload', $session->read('same-second'));
        $this->assertTrue($session->write('same-second', 'payload'));
    }

    public function testUpdateTimestampRestoresRowDeletedAfterRead(): void {
        $session = new Session($this->db, advisory: false);
        $session->write('gc-race', 'payload');
        $session->open('', '');
        $this->assertSame('payload', $session->read('gc-race'));
        $this->db->exec('DELETE FROM sessions WHERE session_id = ?', ['gc-race']);

        $this->assertTrue($session->updateTimestamp('gc-race', 'payload'));
        $this->assertSame('payload', $this->db->var('SELECT data FROM sessions WHERE session_id = ?', ['gc-race']));
    }

    public function testWriteDoesFullInsertWhenDataChanged(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db->pdo()->exec('CREATE TABLE sessions (session_id TEXT PRIMARY KEY, data TEXT, ip TEXT, agent TEXT, stamp INTEGER)');

        $session = new Session($db, advisory: false);
        $session->open('', '');
        $session->read('test-change');
        $session->write('test-change', 'data|s:5:"hello";');

        $db->resetRequestState();
        $session->read('test-change');
        $session->write('test-change', 'data|s:7:"changed";');

        $log = $db->queryLog();
        $lastQuery = end($log);
        $this->assertIsArray($lastQuery);
        $this->assertStringContainsString('INSERT', $lastQuery['sql'], 'Changed data should do full INSERT OR REPLACE');
    }

    public function testConstructorAcceptsLockTimeout(): void {
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $session = new Session($db, advisory: true, lockTimeout: 5);
        $this->assertInstanceOf(Session::class, $session);
    }

    public function testAdvisoryMysqlLockUsesConfiguredTimeout(): void {
        $pdo = new \PDO('sqlite::memory:');
        $queries = [];
        $db = $this->createStub(Db::class);
        $db->method('driver')->willReturn('mysql');
        $db->method('pdo')->willReturn($pdo);
        $db->method('var')->willReturnCallback(
            static function (string $sql, mixed $params = null) use (&$queries): mixed {
                $queries[] = [$sql, $params];

                if (str_starts_with($sql, 'SELECT GET_LOCK')) {
                    return 1;
                }
                if (str_starts_with($sql, 'SELECT data FROM sessions')) {
                    return 'payload';
                }
                if (str_starts_with($sql, 'SELECT RELEASE_LOCK')) {
                    return 1;
                }

                return null;
            }
        );

        $session = new Session($db, advisory: true, lockTimeout: 5);
        $session->open('', '');
        $this->assertSame('payload', $session->read('sid-lock'));
        $this->assertTrue($session->close());

        $first = $queries[0] ?? null;
        $this->assertIsArray($first);
        $this->assertSame('SELECT GET_LOCK(?, ?)', $first[0]);
        $this->assertSame(['sess_' . substr(hash('sha256', 'sid-lock'), 0, 32), 5], $first[1]);
    }

    public function testAdvisoryMysqlLockTimeoutFailsClosed(): void {
        $pdo = new \PDO('sqlite::memory:');
        $calls = [];
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'pdo', 'var', 'exec'])
            ->getMock();
        $db->method('driver')->willReturn('mysql');
        $db->method('pdo')->willReturn($pdo);
        $db->method('var')->willReturnCallback(
            static function (string $sql, mixed $params = null) use (&$calls): mixed {
                $calls[] = $sql;
                if (str_starts_with($sql, 'SELECT GET_LOCK')) {
                    return 0; // timeout
                }
                if (str_starts_with($sql, 'SELECT data FROM sessions')) {
                    return 'existing-data';
                }
                return null;
            }
        );
        $db->expects($this->never())->method('exec');

        $session = new Session($db, advisory: true, lockTimeout: 1);
        $session->open('', '');

        $this->assertFalse($session->read('sid-timeout'));
        $this->assertFalse($session->write('sid-timeout', 'new-data'));

        // close completes cleanly
        $this->assertTrue($session->close());

        // RELEASE_LOCK never called (lock was never acquired)
        $releaseCalls = array_filter($calls, fn(string $s) => str_starts_with($s, 'SELECT RELEASE_LOCK'));
        $this->assertEmpty($releaseCalls, 'RELEASE_LOCK must not be called when lock was never acquired');
    }

    public function testAdvisoryLockDoesNotRollbackActiveTransaction(): void {
        $pdo = new \PDO('sqlite::memory:');
        $this->assertTrue($pdo->beginTransaction());

        $db = $this->createStub(Db::class);
        $db->method('driver')->willReturn('mysql');
        $db->method('pdo')->willReturn($pdo);
        $db->method('var')->willReturnCallback(
            static function (string $sql): mixed {
                if (str_starts_with($sql, 'SELECT GET_LOCK')) {
                    return 1;
                }
                if (str_starts_with($sql, 'SELECT data FROM sessions')) {
                    return 'payload';
                }
                if (str_starts_with($sql, 'SELECT RELEASE_LOCK')) {
                    return 1;
                }

                return null;
            }
        );

        $session = new Session($db, advisory: true, lockTimeout: 5);
        $session->open('', '');
        $this->assertSame('payload', $session->read('sid-active-tx'));
        $this->assertTrue($pdo->inTransaction(), 'Session lock acquisition must not rollback an active transaction');
        $this->assertTrue($session->close());
        $this->assertTrue($pdo->rollBack());
    }

    public function testRegenerateReturnsBoolean(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $session = new Session($this->db, advisory: false);
        $session->register(['secure' => false]);
        session_id(bin2hex(random_bytes(8)));
        session_start();

        $this->assertIsBool($session->regenerate(false));

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }

    public function testPullIntendedUrlReturnsStoredUrlAndClearsIt(): void {
        $_SESSION[Session::INTENDED_URL_KEY] = '/admin/dashboard?page=2';

        $url = Session::pullIntendedUrl('/');

        $this->assertSame('/admin/dashboard?page=2', $url);
        $this->assertArrayNotHasKey(Session::INTENDED_URL_KEY, $_SESSION);
    }

    public function testPullIntendedUrlReturnsDefaultWhenNoStoredUrl(): void {
        $url = Session::pullIntendedUrl('/home');

        $this->assertSame('/home', $url);
    }

    public function testPullIntendedUrlReturnsSlashByDefault(): void {
        $url = Session::pullIntendedUrl();

        $this->assertSame('/', $url);
    }

    public function testPullIntendedUrlRejectsExternalUrl(): void {
        $_SESSION[Session::INTENDED_URL_KEY] = 'https://evil.com/steal';

        $url = Session::pullIntendedUrl('/safe');

        $this->assertSame('/safe', $url);
        $this->assertArrayNotHasKey(Session::INTENDED_URL_KEY, $_SESSION);
    }

    public function testPullIntendedUrlRejectsProtocolRelativeUrl(): void {
        $_SESSION[Session::INTENDED_URL_KEY] = '//evil.com/steal';

        $url = Session::pullIntendedUrl('/safe');

        $this->assertSame('/safe', $url);
        $this->assertArrayNotHasKey(Session::INTENDED_URL_KEY, $_SESSION);
    }

    public function testAdvisoryLockDbErrorFailsClosed(): void {
        $pdo = new \PDO('sqlite::memory:');
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'pdo', 'var', 'exec'])
            ->getMock();
        $db->method('driver')->willReturn('mysql');
        $db->method('pdo')->willReturn($pdo);
        $db->method('var')->willReturnCallback(
            static function (string $sql): mixed {
                if (str_starts_with($sql, 'SELECT GET_LOCK')) {
                    throw new \PDOException('MySQL gone away');
                }
                if (str_starts_with($sql, 'SELECT data FROM sessions')) {
                    return 'data-after-error';
                }
                return null;
            }
        );
        $db->expects($this->never())->method('exec');

        $session = new Session($db, advisory: true, lockTimeout: 1);
        $session->open('', '');
        $this->assertFalse($session->read('sid-error'));
        $this->assertFalse($session->write('sid-error', 'new'));
        $this->assertTrue($session->close());
    }

    public function testAdvisoryMysqlNormalFlowWritesAndReleasesLock(): void {
        $pdo = new \PDO('sqlite::memory:');
        $calls = [];
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'pdo', 'var', 'exec'])
            ->getMock();
        $db->method('driver')->willReturn('mysql');
        $db->method('pdo')->willReturn($pdo);
        $db->method('var')->willReturnCallback(
            static function (string $sql, mixed $params = null) use (&$calls): mixed {
                $calls[] = $sql;
                if (str_starts_with($sql, 'SELECT GET_LOCK')) {
                    return 1;
                }
                if (str_starts_with($sql, 'SELECT data FROM sessions')) {
                    return 'orig';
                }
                if (str_starts_with($sql, 'SELECT RELEASE_LOCK')) {
                    return 1;
                }
                return null;
            }
        );
        $db->expects($this->once())
            ->method('exec')
            ->with(
                $this->stringContains('ON DUPLICATE KEY UPDATE'),
                $this->anything(),
            )
            ->willReturn(1);

        $session = new Session($db, advisory: true, lockTimeout: 5);
        $session->open('', '');
        $this->assertSame('orig', $session->read('sid-ok'));
        $this->assertTrue($session->write('sid-ok', 'updated'));

        // close() calls releaseLock() again — must be safe (no-op since lockName already null)
        $this->assertTrue($session->close());

        $releaseCalls = array_filter($calls, fn(string $s) => str_starts_with($s, 'SELECT RELEASE_LOCK'));
        $this->assertCount(1, $releaseCalls, 'RELEASE_LOCK must be called exactly once (by write, not again by close)');
    }

    public function testDestroyFailsWhenAdvisoryLockCannotBeAcquired(): void {
        $pdo = new \PDO('sqlite::memory:');
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'pdo', 'var', 'exec'])
            ->getMock();
        $db->method('driver')->willReturn('mysql');
        $db->method('pdo')->willReturn($pdo);
        $db->method('var')->willReturnCallback(
            static function (string $sql): mixed {
                if (str_starts_with($sql, 'SELECT GET_LOCK')) {
                    return 0; // timeout
                }
                if (str_starts_with($sql, 'SELECT data FROM sessions')) {
                    return 'active-session';
                }
                return null;
            }
        );
        $db->expects($this->never())->method('exec');

        $session = new Session($db, advisory: true, lockTimeout: 1);
        $session->open('', '');
        $this->assertFalse($session->read('sid-destroy'));
        $this->assertFalse($session->destroy('sid-destroy'));
    }

    public function testSqliteAdvisoryModePreventsLostUpdateAcrossProcesses(): void {
        $dir = sys_get_temp_dir() . '/pframe_session_process_' . bin2hex(random_bytes(8));
        $lockDir = $dir . '/locks';
        mkdir($lockDir, 0700, true);
        $dbPath = $dir . '/sessions.sqlite';
        $db = new Db(['dsn' => 'sqlite:' . $dbPath]);
        $db->exec('CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY,
            data TEXT NOT NULL DEFAULT "",
            ip TEXT NOT NULL DEFAULT "",
            agent TEXT NOT NULL DEFAULT "",
            stamp INTEGER NOT NULL DEFAULT 0
        )');

        $workerPath = $dir . '/worker.php';
        file_put_contents($workerPath, $this->sqliteSessionWorkerScript());
        $processes = [];

        try {
            $processes[] = $first = $this->startSessionWorker($workerPath, 'a', $dbPath, $lockDir, $dir);
            $this->waitForMarker($dir . '/a-read');

            $processes[] = $second = $this->startSessionWorker($workerPath, 'b', $dbPath, $lockDir, $dir);
            $outcome = $this->waitForEitherMarker($dir . '/b-blocked', $dir . '/b-read');
            touch($dir . '/allow-a');

            $this->waitForMarker($dir . '/a-done');
            $this->waitForMarker($dir . '/b-done');
            $this->assertSame(0, $this->finishSessionWorker($first));
            $this->assertSame(0, $this->finishSessionWorker($second));
            $processes = [];

            $this->assertSame('blocked', $outcome, 'Second process must not read stale session data while the first holds the lock');
            $this->assertSame('AB', $db->var('SELECT data FROM sessions WHERE session_id = ?', ['shared-sid']));
        } finally {
            foreach ($processes as $process) {
                foreach ($process['pipes'] as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
                if (is_resource($process['process'])) {
                    proc_terminate($process['process'], 9);
                    proc_close($process['process']);
                }
            }
            foreach (glob($lockDir . '/*.lock') ?: [] as $file) {
                unlink($file);
            }
            foreach (glob($dir . '/*') ?: [] as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            if (is_dir($lockDir)) {
                rmdir($lockDir);
            }
            if (is_dir($dir)) {
                rmdir($dir);
            }
        }
    }

    public function testSqliteFileLocksUseBoundedStriping(): void {
        $lockDir = sys_get_temp_dir() . '/pframe_session_stripes_' . bin2hex(random_bytes(8));
        $session = new Session($this->db, advisory: true, lockDir: $lockDir);
        $pathMethod = new \ReflectionMethod($session, 'fileLockPath');
        $paths = [];

        try {
            for ($i = 0; $i < 8192; $i++) {
                $path = (string) $pathMethod->invoke($session, 'sid-' . $i);
                $paths[basename($path)] = true;
            }

            $this->assertLessThanOrEqual(4096, count($paths));
            $invalid = array_filter(
                array_keys($paths),
                static fn(string $filename): bool => preg_match('/^[0-9a-f]{3}\.lock$/', $filename) !== 1,
            );
            $this->assertSame([], array_values($invalid));
        } finally {
            rmdir($lockDir);
        }
    }

    public function testConstructorDefaultLockTimeoutIsFive(): void {
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $session = new Session($db, advisory: true);
        $ref = new \ReflectionClass($session);
        $prop = $ref->getProperty('lockTimeout');
        $this->assertSame(5, $prop->getValue($session));
    }

    /** @return array{process: resource, pipes: array<int, resource>} */
    private function startSessionWorker(
        string $workerPath,
        string $role,
        string $dbPath,
        string $lockDir,
        string $stateDir,
    ): array {
        $pipes = [];
        $process = proc_open(
            [PHP_BINARY, $workerPath, $role, $dbPath, $lockDir, $stateDir],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        $this->assertIsResource($process);

        return ['process' => $process, 'pipes' => $pipes];
    }

    /** @param array{process: resource, pipes: array<int, resource>} $worker */
    private function finishSessionWorker(array $worker): int {
        $output = stream_get_contents($worker['pipes'][1]) ?: '';
        $errors = stream_get_contents($worker['pipes'][2]) ?: '';
        fclose($worker['pipes'][1]);
        fclose($worker['pipes'][2]);
        $exitCode = proc_close($worker['process']);
        $this->assertSame('', $errors, $errors . $output);

        return $exitCode;
    }

    private function waitForMarker(string $path): void {
        $deadline = microtime(true) + 5;
        while (!is_file($path) && microtime(true) < $deadline) {
            usleep(10_000);
        }
        $this->assertFileExists($path, 'Timed out waiting for marker: ' . basename($path));
    }

    private function waitForEitherMarker(string $blockedPath, string $readPath): string {
        $deadline = microtime(true) + 5;
        while (!is_file($blockedPath) && !is_file($readPath) && microtime(true) < $deadline) {
            usleep(10_000);
        }
        $this->assertTrue(
            is_file($blockedPath) || is_file($readPath),
            'Timed out waiting for the second session worker',
        );

        return is_file($blockedPath) ? 'blocked' : 'read';
    }

    private function sqliteSessionWorkerScript(): string {
        $source = var_export(dirname(__DIR__, 2) . '/src/PFrame.php', true);

        return <<<PHP
<?php
declare(strict_types=1);

require {$source};

use PFrame\\Db;
use PFrame\\Session;

[, \$role, \$dbPath, \$lockDir, \$stateDir] = \$argv;
ini_set('log_errors', '1');
ini_set('error_log', \$stateDir . '/worker-' . \$role . '.log');
\$db = new Db(['dsn' => 'sqlite:' . \$dbPath]);
\$session = new Session(\$db, advisory: true, lockTimeout: 0, lockDir: \$lockDir);

if (\$role === 'a') {
    \$data = \$session->read('shared-sid');
    if (!is_string(\$data)) {
        throw new RuntimeException('First worker could not read the session');
    }
    touch(\$stateDir . '/a-read');
    while (!is_file(\$stateDir . '/allow-a')) {
        usleep(10_000);
    }
    if (!\$session->write('shared-sid', \$data . 'A')) {
        throw new RuntimeException('First worker could not write the session');
    }
    touch(\$stateDir . '/a-done');
    exit(0);
}

\$data = \$session->read('shared-sid');
if (\$data === false) {
    touch(\$stateDir . '/b-blocked');
    while (!is_file(\$stateDir . '/a-done')) {
        usleep(10_000);
    }
    \$data = \$session->read('shared-sid');
    if (!is_string(\$data)) {
        throw new RuntimeException('Second worker could not retry the session read');
    }
} else {
    touch(\$stateDir . '/b-read');
    while (!is_file(\$stateDir . '/a-done')) {
        usleep(10_000);
    }
}
if (!\$session->write('shared-sid', \$data . 'B')) {
    throw new RuntimeException('Second worker could not write the session');
}
touch(\$stateDir . '/b-done');
PHP;
    }
}
