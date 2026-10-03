<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\App;
use PFrame\Controller;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class FullCycleTest extends TestCase {
    protected function tearDown(): void {
        $_SESSION = [];
    }

    public function testBeforeRouteGuard(): void {
        $_SESSION = [];
        TestGuardedCtrl::$runs = 0;
        $app = new App();
        $app->get('/guarded', TestGuardedCtrl::class, 'secret');

        $response = $app->handle(new Request(method: 'GET', path: '/guarded'));
        $this->assertSame(401, $response->status);
        $this->assertStringNotContainsString('secret', $response->body);
        $this->assertSame(0, TestGuardedCtrl::$runs, 'A denied request must not execute the action');

        $_SESSION = ['user' => ['id' => 1]];
        $response = $app->handle(new Request(method: 'GET', path: '/guarded'));
        $this->assertSame(200, $response->status);
        $this->assertSame('secret', $response->body);
        $this->assertSame(1, TestGuardedCtrl::$runs);
    }
}

class TestGuardedCtrl extends Controller {
    public static int $runs = 0;

    public function beforeRoute(): void {
        $this->requireAuth();
    }

    public function secret(): Response {
        self::$runs++;
        return new Response('secret');
    }
}
