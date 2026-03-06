<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\HttpException;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase;

class ErrorHandlingTest extends TestCase {
    public function testDefaultHtml404And500(): void {
        $app = new App();
        $app->get('/missing', ErrorTestController::class, 'throw404');
        $app->get('/fail', ErrorTestController::class, 'throw500');

        $response404 = $app->handle(new Request(method: 'GET', path: '/missing'));
        $this->assertSame(404, $response404->status);
        $this->assertSame('text/html; charset=UTF-8', $response404->headers['Content-Type'] ?? null);
        $this->assertStringContainsString('<!doctype html>', strtolower($response404->body));
        $this->assertStringContainsString('404', $response404->body);
        $this->assertStringContainsString('Not Found', $response404->body);

        $response500 = $app->handle(new Request(method: 'GET', path: '/fail'));
        $this->assertSame(500, $response500->status);
        $this->assertSame('text/html; charset=UTF-8', $response500->headers['Content-Type'] ?? null);
        $this->assertStringContainsString('500', $response500->body);
        $this->assertStringContainsString('Internal Server Error', $response500->body);
    }

    public function testMessageHiddenFor500OnDebug0(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/fail', ErrorTestController::class, 'throw500');

        $response = $app->handle(new Request(method: 'GET', path: '/fail'));
        $this->assertSame(500, $response->status);
        $this->assertStringContainsString('500', $response->body);
        $this->assertStringContainsString('Internal Server Error', $response->body);
        $this->assertStringNotContainsString('Sensitive 500 message', $response->body);
    }

    public function testMessageVisibleFor500OnDebug1(): void {
        $app = new App();
        $app->setConfig('debug', 1);
        $app->get('/fail', ErrorTestController::class, 'throw500');

        $response = $app->handle(new Request(method: 'GET', path: '/fail'));
        $this->assertSame(500, $response->status);
        $this->assertStringContainsString('Sensitive 500 message', $response->body);
    }

    public function testMessageVisibleFor422Always(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/invalid', ErrorTestController::class, 'throw422');

        $response = $app->handle(new Request(method: 'GET', path: '/invalid'));
        $this->assertSame(422, $response->status);
        $this->assertStringContainsString('Email is already taken', $response->body);
    }

    public function test405PreservesAllowHeader(): void {
        $app = new App();
        $app->get('/ping', ErrorTestController::class, 'throw404');

        $response = $app->handle(new Request(method: 'POST', path: '/ping'));
        $this->assertSame(405, $response->status);
        $this->assertSame('GET, HEAD', $response->headers['Allow'] ?? null);
        $this->assertSame('text/html; charset=UTF-8', $response->headers['Content-Type'] ?? null);
    }

    public function test3xxPassThroughSkipsCustomHandler(): void {
        $app = new App();
        $app->get('/redirect', ErrorTestController::class, 'throw302');

        $customHandlerCalled = false;
        $app->setErrorPageHandler(function () use (&$customHandlerCalled): Response {
            $customHandlerCalled = true;
            return new Response('custom');
        });

        $response = $app->handle(new Request(method: 'GET', path: '/redirect'));

        $this->assertSame(302, $response->status);
        $this->assertSame('Moved Temporarily', $response->body);
        $this->assertSame('/target', $response->headers['Location'] ?? null);
        $this->assertFalse($customHandlerCalled);
    }

    public function testCustomHandlerCanReturnCustomResponseAndGetsContext(): void {
        $app = new App();
        $app->get('/missing', ErrorTestController::class, 'throw404');
        $request = new Request(method: 'GET', path: '/missing');

        $capturedException = null;
        $capturedRequest = null;
        $capturedApp = null;
        $app->setErrorPageHandler(function (HttpException $e, Request $req, App $currentApp) use (&$capturedException, &$capturedRequest, &$capturedApp): Response {
            $capturedException = $e;
            $capturedRequest = $req;
            $capturedApp = $currentApp;
            return new Response('custom-response', 418, ['X-Error-Handler' => 'yes']);
        });

        $response = $app->handle($request);

        $this->assertSame(418, $response->status);
        $this->assertSame('custom-response', $response->body);
        $this->assertSame('yes', $response->headers['X-Error-Handler'] ?? null);
        $this->assertInstanceOf(HttpException::class, $capturedException);
        $this->assertSame(404, $capturedException->statusCode);
        $this->assertSame($request, $capturedRequest);
        $this->assertSame($app, $capturedApp);
    }

    public function testCustomHandlerNullFallsBack(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/fail', ErrorTestController::class, 'throw500');

        $called = false;
        $app->setErrorPageHandler(function (HttpException $e, Request $req, App $currentApp) use (&$called): ?Response {
            $called = true;
            return null;
        });

        $response = $app->handle(new Request(method: 'GET', path: '/fail'));

        $this->assertTrue($called);
        $this->assertSame(500, $response->status);
        $this->assertSame('text/html; charset=UTF-8', $response->headers['Content-Type'] ?? null);
        $this->assertStringContainsString('500', $response->body);
        $this->assertStringContainsString('Internal Server Error', $response->body);
    }

    public function testAjaxFallbackIsPlainTextAndDebug3ShowsExceptionMessage(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/forbidden', ErrorTestController::class, 'throw403');

        $ajaxRequest = new Request(
            method: 'GET',
            path: '/forbidden',
            headers: ['X-Requested-With' => 'XMLHttpRequest'],
        );

        $response = $app->handle($ajaxRequest);
        $this->assertSame(403, $response->status);
        $this->assertSame('text/plain; charset=UTF-8', $response->headers['Content-Type'] ?? null);
        $this->assertSame('Forbidden', $response->body);
        $this->assertStringNotContainsString('<html', strtolower($response->body));

        $app = new App();
        $app->setConfig('debug', 3);
        $app->get('/forbidden', ErrorTestController::class, 'throw403');

        $response = $app->handle($ajaxRequest);
        $this->assertSame(403, $response->status);
        $this->assertSame('Forbidden debug details', $response->body);
    }

    public function testCustomHandlerCanInterceptAjax(): void {
        $app = new App();
        $app->get('/forbidden', ErrorTestController::class, 'throw403');

        $app->setErrorPageHandler(function (HttpException $e, Request $request, App $currentApp): ?Response {
            if ($request->isAjax()) {
                return new Response('ajax-custom', 409, ['Content-Type' => 'text/plain; charset=UTF-8']);
            }
            return null;
        });

        $response = $app->handle(new Request(
            method: 'GET',
            path: '/forbidden',
            headers: ['X-Requested-With' => 'XMLHttpRequest'],
        ));

        $this->assertSame(409, $response->status);
        $this->assertSame('ajax-custom', $response->body);
        $this->assertSame('text/plain; charset=UTF-8', $response->headers['Content-Type'] ?? null);
    }

    public function testUnhandledRuntimeExceptionUsesSamePipelineDefaultAndCustom(): void {
        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/runtime', ErrorTestController::class, 'throwRuntime');

        $response = $app->handle(new Request(method: 'GET', path: '/runtime'));
        $this->assertSame(500, $response->status);
        $this->assertSame('text/html; charset=UTF-8', $response->headers['Content-Type'] ?? null);
        $this->assertStringContainsString('500', $response->body);
        $this->assertStringContainsString('Internal Server Error', $response->body);
        $this->assertStringNotContainsString('Runtime failure details', $response->body);

        $app = new App();
        $app->setConfig('debug', 0);
        $app->get('/runtime', ErrorTestController::class, 'throwRuntime');

        $customCalled = false;
        $app->setErrorPageHandler(function (HttpException $e, Request $request, App $currentApp) use (&$customCalled): Response {
            $customCalled = true;
            $this->assertSame(500, $e->statusCode);
            $this->assertSame('/runtime', $request->path);
            return new Response('runtime-custom', 590);
        });

        $response = $app->handle(new Request(method: 'GET', path: '/runtime'));
        $this->assertTrue($customCalled);
        $this->assertSame(590, $response->status);
        $this->assertSame('runtime-custom', $response->body);
    }

    public function testUnmatchedRoute404GetsDefaultHtml(): void {
        $app = new App();

        $response = $app->handle(new Request(method: 'GET', path: '/not-registered'));

        $this->assertSame(404, $response->status);
        $this->assertSame('text/html; charset=UTF-8', $response->headers['Content-Type'] ?? null);
        $this->assertStringContainsString('404', $response->body);
        $this->assertStringContainsString('Not Found', $response->body);
        $this->assertStringContainsString('<!doctype html>', strtolower($response->body));
    }
}
