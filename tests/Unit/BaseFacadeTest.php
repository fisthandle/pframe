<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\Db;
use PFrame\Base;
use PHPUnit\Framework\TestCase;

class BaseFacadeTest extends TestCase {
    public function testAppReturnsInstance(): void {
        $app = new App();
        $this->assertSame($app, Base::app());
    }

    public function testConfigViaFacade(): void {
        $app = new App();
        $app->setConfig('test_key', 'test_val');
        $this->assertSame('test_val', Base::config('test_key'));
    }

    public function testDbShortcutsAndFlash(): void {
        $app = new App();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)');
        $app->setDb($db);

        Base::exec('INSERT INTO items (name) VALUES (?)', ['a']);
        $id = Base::insertGetId('INSERT INTO items (name) VALUES (?)', ['b']);

        $this->assertSame(2, $id);
        $this->assertSame(2, Base::var('SELECT COUNT(*) FROM items'));
        $this->assertSame('a', Base::row('SELECT * FROM items WHERE id = 1')['name']);
        $this->assertSame(['a', 'b'], Base::col('SELECT name FROM items ORDER BY id'));
        $this->assertCount(2, Base::results('SELECT * FROM items'));
        $this->assertInstanceOf(\PFrame\Flash::class, Base::flash());

        Base::batchInsert('items', ['name'], [['c'], ['d']]);
        $this->assertSame(4, Base::var('SELECT COUNT(*) FROM items'));
    }

    public function testUrlShortcut(): void {
        $app = new App();
        $app->get('/o/{slug}', FacadeStubCtrl::class, 'index', name: 'ad.show');

        $this->assertSame('/o/s', Base::url('ad.show', ['slug' => 's']));
    }
}

class FacadeStubCtrl {
    public function index(): \PFrame\Response {
        return new \PFrame\Response('ok');
    }
}
