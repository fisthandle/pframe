<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Db;
use PFrame\Session;
use PHPUnit\Framework\TestCase;

class SessionTest extends TestCase {
    private Db $db;

    protected function setUp(): void {
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
}
