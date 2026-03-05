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

    public function testWriteFailsWhenLockWasNotAcquired(): void {
        $session = new Session($this->db, advisory: false);
        $id = bin2hex(random_bytes(16));

        $ref = new \ReflectionClass($session);
        $lockProp = $ref->getProperty('lockAcquired');
        $lockProp->setAccessible(true);
        $lockProp->setValue($session, false);

        $written = $session->write($id, 'locked-out-data');

        $this->assertFalse($written);
        $this->assertSame('', $session->read($id));
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
}
