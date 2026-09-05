<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\App;
use PFrame\Controller;
use PFrame\Csrf;
use PFrame\Response;
use PFrame\View;
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
        $this->app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $this->app->get('/', HttpTestingHomeCtrl::class, 'index');
        $this->app->get('/user/{id}', HttpTestingUserCtrl::class, 'show');
        $this->app->post('/submit', HttpTestingFormCtrl::class, 'store');
        $this->app->route('PUT', '/item/{id}', HttpTestingFormCtrl::class, 'update');
        $this->app->route('PATCH', '/item/{id}', HttpTestingFormCtrl::class, 'patch');
        $this->app->route('DELETE', '/item/{id}', HttpTestingFormCtrl::class, 'destroy');
        $this->app->get('/json', HttpTestingJsonCtrl::class, 'index');
        $this->app->post('/json', HttpTestingJsonCtrl::class, 'store');
        $this->app->get('/inspect', HttpTestingInspectCtrl::class, 'index');
        $this->app->get('/query-count', HttpTestingQueryCtrl::class, 'index');
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

    public function testPostJsonSendsCsrfViaHeaderNotPost(): void {
        $this->postJson('/json', ['name' => 'test']);
        $this->assertOk();
        $body = json_decode($this->response->body, true);
        $this->assertSame('header', $body['csrf_source'], 'CSRF should come from X-Csrf-Token header, not form field');
    }

    public function testPostJsonWithoutCsrfFails(): void {
        $this->withoutCsrf()->postJson('/json', ['name' => 'Joe']);
        $this->assertForbidden();
    }

    public function testWithHeadersSendsCustomHeaders(): void {
        $this->withHeaders(['X-Custom' => 'test'])->get('/inspect');
        $this->assertOk();
        $this->assertJsonContains(['custom' => 'test']);
    }

    public function testAsAjaxSetsXmlHttpRequest(): void {
        $this->asAjax()->get('/inspect');
        $this->assertOk();
        $this->assertJsonContains(['is_ajax' => true]);
    }

    public function testWithoutCsrfResetsAfterRequest(): void {
        $this->withoutCsrf()->post('/submit', ['title' => 'X']);
        $this->assertForbidden();

        $this->post('/submit', ['title' => 'Y']);
        $this->assertOk();
    }

    public function testEachCallResetsRequestDiagnosticsWithoutRollingBackTestTransaction(): void {
        $db = $this->app->db();
        $db->var('SELECT 1');
        $this->app->setLastView(new View(__DIR__ . '/../../fixtures/templates'));
        $db->begin();

        try {
            $this->get('/query-count');
            $this->assertJsonContains(['query_count' => 1, 'last_view_is_null' => true]);

            $this->get('/query-count');
            $this->assertJsonContains(['query_count' => 1, 'last_view_is_null' => true]);
            $this->assertTrue($db->trans(), 'HTTP helper must preserve the surrounding test transaction');
        } finally {
            if ($db->trans()) {
                $db->rollbackAll();
            }
            $db->resetRequestState();
        }
    }

    public function testPostJsonFailureResetsFluentState(): void {
        $stream = fopen('php://memory', 'r');
        $this->assertNotFalse($stream);

        $error = null;
        try {
            $this->withHeaders(['X-Custom' => 'must-not-leak'])
                ->withoutCsrf()
                ->postJson('/json', ['stream' => $stream]);
        } catch (\JsonException $e) {
            $error = $e;
        } finally {
            fclose($stream);
        }

        $this->assertInstanceOf(\JsonException::class, $error);

        $this->get('/inspect');
        $this->assertJsonContains(['custom' => null, 'is_ajax' => false]);

        $this->post('/submit', ['title' => 'state-reset']);
        $this->assertOk();
    }

    public function testEachCallPreservesNestedTransactionRollback(): void {
        $db = $this->app->db();
        $db->exec('CREATE TABLE items (name TEXT)');
        $db->begin();

        try {
            $db->exec('INSERT INTO items (name) VALUES (?)', ['outer']);
            $db->begin();
            $db->exec('INSERT INTO items (name) VALUES (?)', ['inner']);

            $this->get('/query-count');
            $this->assertOk();
            $db->commit();

            $this->assertTrue($db->trans(), 'Committing the savepoint must preserve the test transaction');
            $db->rollback();
            $this->assertSame(0, $db->var('SELECT COUNT(*) FROM items'));
        } finally {
            $db->rollbackAll();
        }
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
        $this->validateCsrf();
        $json = $this->request->jsonBody() ?? [];
        $source = $this->request->header('X-Csrf-Token') !== null
            ? 'header'
            : ($this->request->post(Csrf::FIELD_NAME) !== null ? 'post' : 'missing');
        return Response::json([
            'name' => $json['name'] ?? null,
            'is_ajax' => $this->request->isAjax(),
            'content_type' => $this->request->header('Content-Type'),
            'csrf_source' => $source,
        ]);
    }
}

class HttpTestingInspectCtrl extends Controller {
    public function index(): Response {
        return Response::json([
            'custom' => $this->request->header('X-Custom'),
            'is_ajax' => $this->request->isAjax(),
        ]);
    }
}

class HttpTestingQueryCtrl extends Controller {
    public function index(): Response {
        $app = App::instance();
        $lastViewIsNull = $app->lastView() === null;
        $db = $app->db();
        $db->var('SELECT 1');

        return Response::json([
            'query_count' => $db->queryCount(),
            'last_view_is_null' => $lastViewIsNull,
        ]);
    }
}
