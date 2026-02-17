<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\App;
use PFrame\Controller;
use PFrame\Response;
use PFrame\Testing\HttpTesting;
use PFrame\Testing\ResponseAssertions;
use PHPUnit\Framework\TestCase;

class HttpTestingTest extends TestCase {
    use HttpTesting, ResponseAssertions;

    protected App $app;

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
        $this->app = new App();
        $this->app->get('/', HttpTestingHomeCtrl::class, 'index');
        $this->app->get('/user/{id}', HttpTestingUserCtrl::class, 'show');
        $this->app->post('/submit', HttpTestingFormCtrl::class, 'store');
        $this->app->route('PUT', '/item/{id}', HttpTestingFormCtrl::class, 'update');
        $this->app->route('PATCH', '/item/{id}', HttpTestingFormCtrl::class, 'patch');
        $this->app->route('DELETE', '/item/{id}', HttpTestingFormCtrl::class, 'destroy');
        $this->app->get('/json', HttpTestingJsonCtrl::class, 'index');
        $this->app->post('/json', HttpTestingJsonCtrl::class, 'store');
    }

    protected function tearDown(): void {
        $_SESSION = [];
        parent::tearDown();
    }

    public function testGetReturnsResponse(): void {
        $this->get('/');
        $this->assertOk();
        $this->assertSee('Welcome');
    }

    public function testGetWithRouteParam(): void {
        $this->get('/user/42');
        $this->assertOk();
        $this->assertSee('User 42');
    }

    public function testGet404(): void {
        $this->get('/nonexistent');
        $this->assertNotFound();
    }

    public function testPostInjectsCsrfAutomatically(): void {
        $this->post('/submit', ['title' => 'Test']);
        $this->assertOk();
        $this->assertSee('title=Test');
    }

    public function testPostWithoutCsrfFails(): void {
        $this->withoutCsrf()->post('/submit', ['title' => 'Test']);
        $this->assertForbidden();
    }

    public function testPutInjectsCsrf(): void {
        $this->put('/item/5', ['name' => 'Updated']);
        $this->assertOk();
        $this->assertSee('updated 5');
    }

    public function testDeleteInjectsCsrf(): void {
        $this->delete('/item/5');
        $this->assertOk();
        $this->assertSee('deleted 5');
    }

    public function testPatchInjectsCsrf(): void {
        $this->patch('/item/5', ['name' => 'Patched']);
        $this->assertOk();
        $this->assertSee('patched 5');
    }

    public function testGetJsonResponse(): void {
        $this->get('/json');
        $this->assertOk();
        $this->assertJsonContains(['items' => [1, 2, 3]]);
    }

    public function testPostJsonSendsJsonBodyAndAjaxHeaders(): void {
        $this->postJson('/json', ['name' => 'Joe']);
        $this->assertOk();
        $this->assertJsonContains([
            'name' => 'Joe',
            'is_ajax' => true,
            'content_type' => 'application/json',
        ]);
    }

    public function testWithHeadersSendsCustomHeaders(): void {
        $this->withHeaders(['X-Custom' => 'test'])->get('/');
        $this->assertOk();
    }

    public function testAsAjaxSetsXmlHttpRequest(): void {
        $this->asAjax()->get('/');
        $this->assertOk();
    }

    public function testWithoutCsrfResetsAfterRequest(): void {
        $this->withoutCsrf()->post('/submit', ['title' => 'X']);
        $this->assertForbidden();

        $this->post('/submit', ['title' => 'Y']);
        $this->assertOk();
    }
}

class HttpTestingHomeCtrl extends Controller {
    public function index(): Response {
        return new Response('Welcome');
    }
}

class HttpTestingUserCtrl extends Controller {
    public function show(): Response {
        return new Response('User ' . $this->param('id'));
    }
}

class HttpTestingFormCtrl extends Controller {
    public function beforeRoute(): void {
        $this->validateCsrf();
    }

    public function store(): Response {
        return new Response('title=' . $this->request->post('title'));
    }

    public function update(): Response {
        return new Response('updated ' . $this->param('id'));
    }

    public function patch(): Response {
        return new Response('patched ' . $this->param('id'));
    }

    public function destroy(): Response {
        return new Response('deleted ' . $this->param('id'));
    }
}

class HttpTestingJsonCtrl extends Controller {
    public function index(): Response {
        return Response::json(['items' => [1, 2, 3]]);
    }

    public function store(): Response {
        $json = $this->request->jsonBody() ?? [];
        return Response::json([
            'name' => $json['name'] ?? null,
            'is_ajax' => $this->request->isAjax(),
            'content_type' => $this->request->header('Content-Type'),
        ]);
    }
}
