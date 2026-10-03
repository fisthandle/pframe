<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\App;
use PFrame\Controller;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class FullCycleTest extends TestCase {
    public function testBeforeRouteGuard(): void {
        $_SESSION = [];
        $app = new App();
        $app->get('/guarded', TestGuardedCtrl::class, 'secret');

        $response = $app->handle(new Request(method: 'GET', path: '/guarded'));
        $this->assertSame(401, $response->status);
    }
}

class TestGuardedCtrl extends Controller {
    public function beforeRoute(): void {
        $this->requireAuth();
    }

    public function secret(): Response {
        return new Response('secret');
    }
}
