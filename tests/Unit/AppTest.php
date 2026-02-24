<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\Csrf;
use PFrame\HttpException;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class AppTest extends TestCase {
    public function testRouteRegistration(): void {
        $app = new App();
        $app->get('/hello', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/hello'));
        $this->assertSame(200, $response->status);
        $this->assertSame('hello world', $response->body);
    }

    public function testRouteParams(): void {
        $app = new App();
        $app->get('/greet/{name}', HelloStub::class, 'greet');

        $response = $app->handle(new Request(method: 'GET', path: '/greet/Joe'));
        $this->assertSame('Hello Joe', $response->body);
    }

    public function testStaticRouteMatchesWithTrailingSlash(): void {
        $app = new App();
        $app->get('/about/', StaticRouteStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/about'));
        $this->assertSame(200, $response->status);
        $this->assertSame('about', $response->body);
    }

    public function test404(): void {
        $app = new App();
        $response = $app->handle(new Request(method: 'GET', path: '/nope'));
        $this->assertSame(404, $response->status);
    }

    public function testGlobalMiddleware(): void {
        $app = new App();
        $app->addMiddleware(function (Request $req, callable $next): Response {
            $response = $next($req);
            $response->headers['X-Test'] = 'passed';
            return $response;
        });
        $app->get('/hello', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/hello'));
        $this->assertSame('passed', $response->headers['X-Test'] ?? null);
    }

    public function testRouteMiddleware(): void {
        $app = new App();
        $authMw = function (Request $req, callable $next): Response {
            return new Response('blocked', 403);
        };
        $app->get('/secret', HelloStub::class, 'index', mw: [$authMw]);

        $response = $app->handle(new Request(method: 'GET', path: '/secret'));
        $this->assertSame(403, $response->status);
        $this->assertSame('blocked', $response->body);
    }

    public function testPostRoute(): void {
        $app = new App();
        $app->post('/submit', HelloStub::class, 'submit');

        $response = $app->handle(new Request(method: 'POST', path: '/submit', post: ['val' => 'ok']));
        $this->assertSame('submitted', $response->body);
    }

    public function testNamedRouteUrl(): void {
        $app = new App();
        $app->get('/o/{slug}', HelloStub::class, 'index', name: 'ad.show');
        $this->assertSame('/o/test', $app->url('ad.show', ['slug' => 'test']));
        $this->assertSame('/o/a%20b', $app->url('ad.show', ['slug' => 'a b']));
    }

    public function testNamedRouteUrlAddsQueryStringForExtraParams(): void {
        $app = new App();
        $app->get('/o/{slug}', HelloStub::class, 'index', name: 'ad.show');

        $this->assertSame('/o/test?page=2&sort=asc', $app->url('ad.show', [
            'slug' => 'test',
            'page' => 2,
            'sort' => 'asc',
        ]));
    }

    public function testDuplicateRouteNameThrows(): void {
        $app = new App();
        $app->get('/first', HelloStub::class, 'index', name: 'dup');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Duplicate route name: dup');
        $app->get('/second', HelloStub::class, 'index', name: 'dup');
    }

    public function testUrlMissingRouteParamThrows(): void {
        $app = new App();
        $app->get('/o/{slug}', HelloStub::class, 'index', name: 'ad.show');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Missing route parameter "slug"');
        $app->url('ad.show');
    }

    public function testRouteGroupAppliesPrefixNamePrefixAndMiddleware(): void {
        $app = new App();
        $groupMw = function (Request $req, callable $next): Response {
            $resp = $next($req);
            $resp->headers['X-Group'] = 'yes';
            return $resp;
        };

        $app->group('/admin', function (App $app): void {
            $app->get('/users/{id}', HelloStub::class, 'index', name: 'users.show');
        }, mw: [$groupMw], namePrefix: 'admin.');

        $response = $app->handle(new Request(method: 'GET', path: '/admin/users/42'));
        $this->assertSame(200, $response->status);
        $this->assertSame('yes', $response->headers['X-Group'] ?? null);
        $this->assertSame('/admin/users/42', $app->url('admin.users.show', ['id' => 42]));
    }

    public function testNestedRouteGroupsComposePrefixAndNamePrefix(): void {
        $app = new App();

        $app->group('/api', function (App $app): void {
            $app->group('/v1', function (App $app): void {
                $app->get('/ping', HelloStub::class, 'index', name: 'ping');
            }, namePrefix: 'v1.');
        }, namePrefix: 'api.');

        $response = $app->handle(new Request(method: 'GET', path: '/api/v1/ping'));
        $this->assertSame(200, $response->status);
        $this->assertSame('/api/v1/ping', $app->url('api.v1.ping'));
    }

    public function testAjaxRoute(): void {
        $app = new App();
        $app->post('/api/vote', HelloStub::class, 'submit', ajax: true);

        $response = $app->handle(new Request(method: 'POST', path: '/api/vote'));
        $this->assertSame(404, $response->status);

        $response = $app->handle(new Request(
            method: 'POST',
            path: '/api/vote',
            headers: ['X-Requested-With' => 'XMLHttpRequest'],
        ));
        $this->assertSame(200, $response->status);
    }

    public function testConfig(): void {
        $app = new App();
        $app->loadConfig(__DIR__ . '/../fixtures/config/app.php');
        $this->assertSame('TestApp', $app->config('app_name'));
        $this->assertSame('localhost', $app->config('db.host'));
        $this->assertNull($app->config('nonexistent'));
        $this->assertSame('fallback', $app->config('nonexistent', 'fallback'));
    }

    public function testSetConfigDotNotation(): void {
        $app = new App();
        $app->setConfig('db.host', '127.0.0.1');
        $app->setConfig('db.port', 3306);
        $this->assertSame('127.0.0.1', $app->config('db.host'));
        $this->assertSame(3306, $app->config('db.port'));
    }

    public function testConfigLoadErrors(): void {
        $this->expectException(\RuntimeException::class);
        (new App())->loadConfig(__DIR__ . '/../fixtures/config/missing.php');
    }

    public function testUrlMissingRouteThrows(): void {
        $this->expectException(\RuntimeException::class);
        (new App())->url('missing.route');
    }

    public function testRouteWildcardMatch(): void {
        $app = new App();
        $app->route('GET', '/assets/*', WildcardCtrl::class, 'show');

        $response = $app->handle(new Request(method: 'GET', path: '/assets/css/main.css'));
        $this->assertSame(200, $response->status);
        $this->assertSame('css/main.css', $response->body);
    }

    public function testRouteWildcardWithParam(): void {
        $app = new App();
        $app->route('GET', '/docs/{lang}/*', WildcardCtrl::class, 'show');

        $response = $app->handle(new Request(method: 'GET', path: '/docs/pl/getting-started/intro'));
        $this->assertSame('getting-started/intro', $response->body);
    }

    public function testMethodNotAllowedReturns405(): void {
        $app = new App();
        $app->get('/ping', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'POST', path: '/ping'));
        $this->assertSame(405, $response->status);
        $this->assertSame('GET, HEAD', $response->headers['Allow'] ?? null);
    }

    public function testMethodNotAllowedSkipsAjaxOnlyRoutesForNonAjaxRequest(): void {
        $app = new App();
        $app->get('/vote', HelloStub::class, 'index');
        $app->post('/vote', HelloStub::class, 'submit', ajax: true);

        $response = $app->handle(new Request(method: 'PUT', path: '/vote'));
        $this->assertSame(405, $response->status);
        $this->assertSame('GET, HEAD', $response->headers['Allow'] ?? null);
    }

    public function testSecurityHeadersMiddlewareAddsDefaults(): void {
        $app = new App();
        $app->addSecurityHeaders();
        $app->get('/', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/', server: ['HTTPS' => 'on']));
        $this->assertSame('DENY', $response->headers['X-Frame-Options'] ?? null);
        $this->assertSame('nosniff', $response->headers['X-Content-Type-Options'] ?? null);
        $this->assertArrayHasKey('Content-Security-Policy', $response->headers);
        $this->assertSame('max-age=63072000; includeSubDomains; preload', $response->headers['Strict-Transport-Security'] ?? null);
    }

    public function testSecurityHeadersDoesNotTrustForwardedProtoFromUntrustedProxy(): void {
        $app = new App();
        $app->setConfig('trusted_proxies', ['10.0.0.1']);
        $app->addSecurityHeaders();
        $app->get('/', HelloStub::class, 'index');

        $response = $app->handle(new Request(
            method: 'GET',
            path: '/',
            server: ['REMOTE_ADDR' => '203.0.113.5'],
            headers: ['X-Forwarded-Proto' => 'https'],
        ));
        $this->assertArrayHasKey('Content-Security-Policy', $response->headers);
        $this->assertArrayNotHasKey('Strict-Transport-Security', $response->headers);
    }

    public function testSecurityHeadersAllowDisablingHsts(): void {
        $app = new App();
        $app->addSecurityHeaders(['Strict-Transport-Security' => null]);
        $app->get('/', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/', server: ['HTTPS' => 'on']));
        $this->assertArrayNotHasKey('Strict-Transport-Security', $response->headers);
    }

    public function testSecurityHeadersTrustForwardedProtoFromTrustedProxy(): void {
        $app = new App();
        $app->setConfig('trusted_proxies', ['10.0.0.1']);
        $app->addSecurityHeaders();
        $app->get('/', HelloStub::class, 'index');

        $response = $app->handle(new Request(
            method: 'GET',
            path: '/',
            server: ['REMOTE_ADDR' => '10.0.0.1'],
            headers: ['X-Forwarded-Proto' => 'https'],
        ));
        $this->assertSame('max-age=63072000; includeSubDomains; preload', $response->headers['Strict-Transport-Security'] ?? null);
    }

    public function testSecurityHeadersDoNotOverrideExistingHeaderCaseInsensitive(): void {
        $app = new App();
        $app->addSecurityHeaders();
        $app->get('/csp', HeaderCtrl::class, 'customCsp');

        $response = $app->handle(new Request(method: 'GET', path: '/csp'));
        $this->assertSame("default-src 'none'", $response->headers['content-security-policy'] ?? null);
        $this->assertArrayNotHasKey('Content-Security-Policy', $response->headers);
    }

    public function testHttpExceptionMessageDependsOnDebug(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/deny', ThrowHttpCtrl::class, 'run');

        $response = $app->handle(new Request(method: 'GET', path: '/deny'));
        $this->assertSame(403, $response->status);
        $this->assertStringContainsString('<!DOCTYPE html>', $response->body);
        $this->assertStringContainsString('Forbidden', $response->body);
        $this->assertStringNotContainsString('blocked by test', $response->body);

        $app = new App();
        $app->setConfig('debug', 3);
        $app->get('/deny', ThrowHttpCtrl::class, 'run');
        $response = $app->handle(new Request(method: 'GET', path: '/deny'));
        $this->assertStringContainsString('blocked by test', $response->body);
    }

    public function testHandleHttpException422PassesMessage(): void {
        $app = new App();
        $app->get('/test-422', Http422Stub::class, 'throwWithMessage');

        $response = $app->handle(new Request(method: 'GET', path: '/test-422'));
        $this->assertSame(422, $response->status);
        $this->assertStringContainsString('<!DOCTYPE html>', $response->body);
        $this->assertStringContainsString('Email jest zajęty', $response->body);
    }

    public function testHandleHttpException422FallbackMessage(): void {
        $app = new App();
        $app->get('/test-422-empty', Http422Stub::class, 'throwEmpty');

        $response = $app->handle(new Request(method: 'GET', path: '/test-422-empty'));
        $this->assertSame(422, $response->status);
        $this->assertStringContainsString('<!DOCTYPE html>', $response->body);
        $this->assertStringContainsString('Unprocessable Entity', $response->body);
    }

    public function testRuntimeExceptionHandled(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/boom', ThrowRuntimeCtrl::class, 'run');

        $response = $app->handle(new Request(method: 'GET', path: '/boom'));
        $this->assertSame(500, $response->status);
        $this->assertStringContainsString('<!DOCTYPE html>', $response->body);
        $this->assertStringContainsString('Internal Server Error', $response->body);
        $this->assertStringNotContainsString('boom', $response->body);

        $app = new App();
        $app->setConfig('debug', 3);
        $app->get('/boom', ThrowRuntimeCtrl::class, 'run');
        $response = $app->handle(new Request(method: 'GET', path: '/boom'));
        $this->assertSame(500, $response->status);
        $this->assertStringContainsString('boom', $response->body);
    }

    public function testBeforeAndAfterRouteHooks(): void {
        $app = new App();
        $app->get('/hooks', HookCtrl::class, 'run');

        $response = $app->handle(new Request(method: 'GET', path: '/hooks'));
        $this->assertSame('after', $response->body);

        $app = new App();
        $app->get('/before', BeforeStopsCtrl::class, 'run');

        $response = $app->handle(new Request(method: 'GET', path: '/before'));
        $this->assertSame('before', $response->body);
    }

    public function testControllerMethodReceivesRequest(): void {
        $app = new App();
        $app->get('/di-test', DIRequestStub::class, 'withRequest');

        $response = $app->handle(new Request(method: 'GET', path: '/di-test'));
        $this->assertSame('GET', $response->body);
    }

    public function testControllerMethodReceivesApp(): void {
        $app = new App();
        $app->get('/di-app', DIAppStub::class, 'withApp');

        $response = $app->handle(new Request(method: 'GET', path: '/di-app'));
        $this->assertSame('has_app', $response->body);
    }

    public function testControllerMethodNoArgsStillWorks(): void {
        $app = new App();
        $app->get('/hello', HelloStub::class, 'index');

        $response = $app->handle(new Request(method: 'GET', path: '/hello'));
        $this->assertSame('hello world', $response->body);
    }

    public function testElapsedTime(): void {
        $app = new App();
        usleep(5000); // 5ms
        $this->assertGreaterThan(0.004, $app->elapsed());
        $this->assertLessThan(1.0, $app->elapsed());
    }

    public function testResetRequestStateResetsElapsed(): void {
        $app = new App();
        usleep(10000); // 10ms
        $before = $app->elapsed();

        $app->resetRequestState();
        $after = $app->elapsed();

        $this->assertGreaterThan(0.009, $before);
        $this->assertLessThan($before, $after);
    }

    public function testResetRequestStatePreservesRoutesAndConfig(): void {
        $app = new App();
        $app->get('/hello', HelloStub::class, 'index');
        $app->setConfig('test_key', 'test_val');

        $app->resetRequestState();

        $response = $app->handle(new Request(method: 'GET', path: '/hello'));
        $this->assertSame(200, $response->status);
        $this->assertSame('hello world', $response->body);
        $this->assertSame('test_val', $app->config('test_key'));
    }

    public function testResetRequestStatePreservesDb(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:']);
        $db = $app->db();

        $app->resetRequestState();

        $this->assertSame($db, $app->db());
    }

    public function testMissingActionHandledAs500(): void {
        $app = new App();
        $app->get('/x', HelloStub::class, 'missingAction');
        $response = $app->handle(new Request(method: 'GET', path: '/x'));
        $this->assertSame(500, $response->status);
    }

    public function testWarningsConvertedTo500(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/warn', WarningCtrl::class, 'run');

        $response = $app->handle(new Request(method: 'GET', path: '/warn'));
        $this->assertSame(500, $response->status);
    }

    public function testCsrfArrayTokenReturns403Not500(): void {
        $_SESSION = [];
        Csrf::token();

        $app = new App();
        $app->post('/csrf-test', CsrfTestCtrl::class, 'run');

        $request = new Request(
            method: 'POST',
            path: '/csrf-test',
            post: [Csrf::FIELD_NAME => ['array', 'value']],
        );
        $response = $app->handle($request);

        $this->assertSame(403, $response->status);
    }

    public function testAppInstanceThrowsWhenRequestedAsDifferentSubclass(): void {
        new App();

        $this->expectException(\LogicException::class);
        AppTestCustomApp::instance();
    }

    public function testAppInstanceReturnsSameSubclassInstance(): void {
        $app = new AppTestCustomApp();
        $this->assertSame($app, AppTestCustomApp::instance());
    }
}

class HelloStub {
    public Request $request;

    public function index(): Response {
        return new Response('hello world');
    }

    public function greet(): Response {
        return new Response('Hello ' . $this->request->param('name'));
    }

    public function submit(): Response {
        return new Response('submitted');
    }
}

class WildcardCtrl {
    public Request $request;

    public function show(): Response {
        return new Response($this->request->param('*', ''));
    }
}

class StaticRouteStub {
    public Request $request;

    public function index(): Response {
        return new Response('about');
    }
}

class ThrowHttpCtrl {
    public function run(): Response {
        throw HttpException::forbidden('blocked by test');
    }
}

class Http422Stub {
    public Request $request;

    public function throwWithMessage(): never {
        throw new HttpException(422, 'Email jest zajęty');
    }

    public function throwEmpty(): never {
        throw new HttpException(422);
    }
}

class ThrowRuntimeCtrl {
    public function run(): Response {
        throw new \RuntimeException('boom');
    }
}

class HookCtrl {
    public function beforeRoute(): void {
    }

    public function run(): Response {
        return new Response('action');
    }

    public function afterRoute(): Response {
        return new Response('after');
    }
}

class DIRequestStub {
    public Request $request;

    public function withRequest(Request $request): Response {
        return new Response($request->method);
    }
}

class DIAppStub {
    public Request $request;

    public function withApp(App $app): Response {
        return new Response('has_app');
    }
}

class BeforeStopsCtrl {
    public function beforeRoute(): Response {
        return new Response('before');
    }

    public function run(): Response {
        return new Response('action');
    }
}

class WarningCtrl {
    public function run(): Response {
        trigger_error('test warning', E_USER_WARNING);
        return new Response('ok');
    }
}

class HeaderCtrl {
    public function customCsp(): Response {
        return new Response('ok', headers: ['content-security-policy' => "default-src 'none'"]);
    }
}

class CsrfTestCtrl extends \PFrame\Controller {
    public function run(): Response {
        $this->validateCsrf();
        return new Response('ok');
    }
}

class AppTestCustomApp extends App {
}
