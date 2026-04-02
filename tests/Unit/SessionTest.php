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

    public function testSessionWriteWorksWithAdvisoryDisabled(): void {
        $session = new Session($this->db, advisory: false);
        $id = bin2hex(random_bytes(16));

        $session->write($id, serialize(['test' => 'data']));
        $data = $session->read($id);

        $this->assertStringContainsString('test', $data);
    }

    public function testWriteSkipsWhenLockNotAcquired(): void {
        $session = new Session($this->db, advisory: false);
        $id = bin2hex(random_bytes(16));

        $ref = new \ReflectionClass($session);
        $lockProp = $ref->getProperty('lockAcquired');
        $lockProp->setAccessible(true);
        $lockProp->setValue($session, false);

        $this->assertSame('', $session->read($id));
        $this->assertTrue($session->write($id, 'should-not-persist'));

        $data = $this->db->var('SELECT data FROM sessions WHERE session_id = ?', [$id]);
        $this->assertNull($data, 'Data must not be written without advisory lock');
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
        $db = $this->getMockBuilder(Db::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['driver', 'pdo', 'var'])
            ->getMock();
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
        $this->assertSame(['sess_sid-lock', 5], $first[1]);
    }

    public function testAdvisoryMysqlLockTimeoutDegradesToReadOnly(): void {
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

        // read succeeds despite lock timeout
        $this->assertSame('existing-data', $session->read('sid-timeout'));

        // write silently skips (no exception)
        $this->assertTrue($session->write('sid-timeout', 'new-data'));

        // close completes cleanly
        $this->assertTrue($session->close());

        // RELEASE_LOCK never called (lock was never acquired)
        $releaseCalls = array_filter($calls, fn(string $s) => str_starts_with($s, 'SELECT RELEASE_LOCK'));
        $this->assertEmpty($releaseCalls, 'RELEASE_LOCK must not be called when lock was never acquired');
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

    public function testAdvisoryLockDbErrorDegradesToReadOnly(): void {
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
        $this->assertSame('data-after-error', $session->read('sid-error'));
        $this->assertTrue($session->write('sid-error', 'new'));
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

    public function testDestroyExecutesWithoutAdvisoryLock(): void {
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
        $db->expects($this->once())
            ->method('exec')
            ->with(
                'DELETE FROM sessions WHERE session_id = ?',
                ['sid-destroy'],
            )
            ->willReturn(1);

        $session = new Session($db, advisory: true, lockTimeout: 1);
        $session->open('', '');
        $session->read('sid-destroy');
        $this->assertTrue($session->destroy('sid-destroy'));
    }

    public function testConstructorDefaultLockTimeoutIsFive(): void {
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $session = new Session($db, advisory: true);
        $ref = new \ReflectionClass($session);
        $prop = $ref->getProperty('lockTimeout');
        $prop->setAccessible(true);
        $this->assertSame(5, $prop->getValue($session));
    }
}
