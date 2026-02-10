<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\Controller;
use PFrame\Csrf;
use PFrame\Flash;
use PFrame\HttpException;
use PFrame\Middleware;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class MiddlewareTest extends TestCase {
    protected function setUp(): void {
        $_SESSION = [];
        new App();
    }

    public function testAuthRedirectsGuestToLoginRouteAndFlashes(): void {
        $app = new App();
        $app->get('/login', MiddlewareLoginCtrl::class, 'index', name: 'login');

        $mw = Middleware::auth();
        $response = $mw(new Request(method: 'GET', path: '/private'), fn (Request $req): Response => new Response('ok'));

        $this->assertSame(302, $response->status);
        $this->assertSame('/login', $response->headers['Location'] ?? null);
        $this->assertSame('Musisz się zalogować.', (new Flash())->get()[0]['text'] ?? null);
    }

    public function testAuthAllowsAuthenticatedUser(): void {
        $_SESSION['user'] = ['id' => 1];

        $mw = Middleware::auth();
        $response = $mw(new Request(method: 'GET', path: '/private'), fn (Request $req): Response => new Response('ok'));

        $this->assertSame('ok', $response->body);
    }

    public function testAuthFallsBackWhenLoginRouteMissing(): void {
        $mw = Middleware::auth();
        $response = $mw(new Request(method: 'GET', path: '/private'), fn (Request $req): Response => new Response('ok'));

        $this->assertSame('/login', $response->headers['Location'] ?? null);
    }

    public function testCsrfAllowsSafeMethodWithoutToken(): void {
        $mw = Middleware::csrf();
        $response = $mw(new Request(method: 'GET', path: '/x'), fn (Request $req): Response => new Response('ok'));

        $this->assertSame(200, $response->status);
        $this->assertSame('ok', $response->body);
    }

    public function testCsrfRejectsInvalidToken(): void {
        $mw = Middleware::csrf();

        $this->expectException(HttpException::class);
        $mw(new Request(method: 'POST', path: '/x', post: [Csrf::FIELD_NAME => 'bad']), fn (Request $req): Response => new Response('ok'));
    }

    public function testCsrfAcceptsTokenFromPostAndHeader(): void {
        $token = Csrf::token();
        $mw = Middleware::csrf();

        $fromPost = $mw(
            new Request(method: 'POST', path: '/x', post: [Csrf::FIELD_NAME => $token]),
            fn (Request $req): Response => new Response('ok'),
        );
        $this->assertSame(200, $fromPost->status);

        $fromHeader = $mw(
            new Request(method: 'POST', path: '/x', headers: ['X-Csrf-Token' => $token]),
            fn (Request $req): Response => new Response('ok'),
        );
        $this->assertSame(200, $fromHeader->status);
    }
}

class MiddlewareLoginCtrl extends Controller {
    public function index(): Response {
        return new Response('login');
    }
}
