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
            $db->rollback();
        }
        $db->resetRequestState();

        $app->resetRequestState();
        $this->assertSame(0, (int) $db->var('SELECT COUNT(*) FROM items'));
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
}

class CounterCtrl extends Controller {
    public function index(): Response {
        $db = App::instance()->db();
        $db->exec('INSERT INTO hits (ts) VALUES (?)', [date('c')]);
        return new Response(body: 'ok');
    }
}
