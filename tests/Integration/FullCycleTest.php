<?php
declare(strict_types=1);

namespace P1\Tests\Integration;

use P1\App;
use P1\Controller;
use P1\Request;
use P1\Response;
use PHPUnit\Framework\TestCase;

class FullCycleTest extends TestCase {
    public function testFullGetRequest(): void {
        $_SESSION = [];
        $app = new App();
        $app->get('/', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/'));
        $this->assertSame(200, $response->status);
        $this->assertStringContainsString('Welcome', $response->body);
    }

    public function testRouteParams(): void {
        $_SESSION = [];
        $app = new App();
        $app->get('/user/{id}', TestUserCtrl::class, 'show');

        $response = $app->handle(new Request(method: 'GET', path: '/user/42'));
        $this->assertStringContainsString('User 42', $response->body);
    }

    public function test404(): void {
        $app = new App();
        $response = $app->handle(new Request(method: 'GET', path: '/nonexistent'));
        $this->assertSame(404, $response->status);
    }

    public function testGlobalMiddleware(): void {
        $_SESSION = [];
        $app = new App();
        $app->addMiddleware(function (Request $r, callable $next): Response {
            $resp = $next($r);
            $resp->headers['X-Powered-By'] = 'P1';
            return $resp;
        });
        $app->get('/', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/'));
        $this->assertSame('P1', $response->headers['X-Powered-By']);
    }

    public function testBeforeRouteGuard(): void {
        $_SESSION = [];
        $app = new App();
        $app->get('/guarded', TestGuardedCtrl::class, 'secret');

        $response = $app->handle(new Request(method: 'GET', path: '/guarded'));
        $this->assertSame(401, $response->status);
    }

    public function testNamedRouteUrl(): void {
        $app = new App();
        $app->get('/o/{slug}', TestHomeCtrl::class, 'index', name: 'ad.show');
        $this->assertSame('/o/my-ad', $app->url('ad.show', ['slug' => 'my-ad']));
    }

    public function testHeadRouteMatchesGetDefinition(): void {
        $app = new App();
        $app->get('/ping', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'HEAD', path: '/ping'));
        $this->assertSame(200, $response->status);
    }

    public function testMethodNotAllowedReturns405(): void {
        $app = new App();
        $app->get('/only-get', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'POST', path: '/only-get'));
        $this->assertSame(405, $response->status);
        $this->assertSame('GET, HEAD', $response->headers['Allow'] ?? null);
    }

    public function testSecurityHeadersMiddlewareAddsDefaults(): void {
        $app = new App();
        $app->addSecurityHeaders();
        $app->get('/', TestHomeCtrl::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/', server: ['HTTPS' => 'on']));
        $this->assertSame('DENY', $response->headers['X-Frame-Options'] ?? null);
        $this->assertSame('nosniff', $response->headers['X-Content-Type-Options'] ?? null);
        $this->assertArrayHasKey('Content-Security-Policy', $response->headers);
        $this->assertSame('max-age=63072000; includeSubDomains; preload', $response->headers['Strict-Transport-Security'] ?? null);
    }
}

class TestHomeCtrl extends Controller {
    public function index(): Response {
        return new Response('Welcome');
    }
}

class TestUserCtrl extends Controller {
    public function show(): Response {
        return new Response('User ' . $this->param('id'));
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
