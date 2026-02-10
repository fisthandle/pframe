<?php
declare(strict_types=1);

namespace P1\Tests\Unit;

use P1\App;
use P1\Controller;
use P1\Csrf;
use P1\Flash;
use P1\HttpException;
use P1\Request;
use P1\Response;
use PHPUnit\Framework\TestCase;

class ControllerTest extends TestCase {
    protected function setUp(): void {
        $_SESSION = [];
        $app = new App();
        $app->setConfig('view_path', __DIR__ . '/../fixtures/templates');
    }

    public function testJson(): void {
        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->json(['ok' => true]);
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');
        $this->assertSame('{"ok":true}', $ctrl->test()->body);
    }

    public function testJsonError(): void {
        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->jsonError('Bad', 422);
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');
        $this->assertSame(422, $ctrl->test()->status);
    }

    public function testJsonSuccess(): void {
        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->jsonSuccess(['x' => 1]);
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');
        $this->assertSame('{"success":true,"x":1}', $ctrl->test()->body);
    }

    public function testFlashAndRedirect(): void {
        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->flashAndRedirect('success', 'Done!', '/home');
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');

        $response = $ctrl->test();
        $this->assertSame(302, $response->status);
        $this->assertSame('/home', $response->headers['Location']);
        $this->assertSame('Done!', (new Flash())->get()[0]['text']);
    }

    public function testParam(): void {
        $ctrl = new class extends Controller {
            public function test(): string {
                return $this->param('slug', 'default');
            }
        };
        $req = new Request(method: 'GET', path: '/');
        $req->setParams(['slug' => 'hello']);
        $ctrl->request = $req;
        $this->assertSame('hello', $ctrl->test());
    }

    public function testPaginate(): void {
        $ctrl = new class extends Controller {
            public function test(): array {
                return $this->paginate(100, 20);
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/', query: ['page' => '3']);
        $p = $ctrl->test();
        $this->assertSame(3, $p['page']);
        $this->assertSame(40, $p['offset']);
        $this->assertSame(5, $p['total_pages']);
    }

    public function testPaginateClampsToLastPage(): void {
        $ctrl = new class extends Controller {
            public function test(): array {
                return $this->paginate(15, 10);
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/', query: ['page' => '9']);
        $p = $ctrl->test();
        $this->assertSame(2, $p['page']);
        $this->assertSame(10, $p['offset']);
        $this->assertSame(10, $p['per_page']);
        $this->assertArrayNotHasKey('limit', $p);
    }

    public function testPaginateZeroPerPage(): void {
        $ctrl = new class extends Controller {
            public function test(): array {
                return $this->paginate(100, 0);
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');
        $p = $ctrl->test();
        $this->assertSame(1, $p['per_page']);
        $this->assertSame(0, $p['offset']);
    }

    public function testRequireAuthThrowsAndFlashes(): void {
        $ctrl = new class extends Controller {
            public function test(): void {
                $this->requireAuth();
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');

        try {
            $ctrl->test();
            $this->fail('Expected HttpException');
        } catch (HttpException $e) {
            $this->assertSame(401, $e->statusCode);
        }

        $this->assertTrue((new Flash())->has());
    }

    public function testRequireAdmin(): void {
        $ctrl = new class extends Controller {
            public function test(): void {
                $this->requireAdmin();
            }
        };
        $ctrl->request = new Request(method: 'GET', path: '/');

        $_SESSION['user'] = ['id' => 1, 'role' => 'user'];
        try {
            $ctrl->test();
            $this->fail('Expected forbidden');
        } catch (HttpException $e) {
            $this->assertSame(403, $e->statusCode);
        }

        $_SESSION['user'] = ['id' => 1, 'role' => 'admin'];
        $ctrl->test();
        $this->assertTrue(true);
    }

    public function testCurrentUserHelpers(): void {
        $ctrl = new class extends Controller {
            public function test(): array {
                return [
                    'user' => $this->currentUser(),
                    'id' => $this->currentUserId(),
                    'auth' => $this->isAuthenticated(),
                ];
            }
        };

        $ctrl->request = new Request(method: 'GET', path: '/');
        $this->assertSame(['user' => null, 'id' => 0, 'auth' => false], $ctrl->test());

        $_SESSION['user'] = ['id' => 42, 'role' => 'admin'];
        $result = $ctrl->test();
        $this->assertSame(42, $result['id']);
        $this->assertTrue($result['auth']);
    }

    public function testValidateCsrfFromPostAndHeader(): void {
        $token = Csrf::token();

        $ctrl = new class extends Controller {
            public function test(): bool {
                $this->validateCsrf();
                return true;
            }
        };

        $ctrl->request = new Request(method: 'POST', path: '/', post: [Csrf::FIELD_NAME => $token]);
        $this->assertTrue($ctrl->test());

        $ctrl->request = new Request(method: 'POST', path: '/', headers: ['X-Csrf-Token' => $token]);
        $this->assertTrue($ctrl->test());

        $ctrl->request = new Request(method: 'POST', path: '/', headers: ['X-Csrf-Token' => 'bad']);
        $this->expectException(HttpException::class);
        $ctrl->test();
    }

    public function testPostData(): void {
        $ctrl = new class extends Controller {
            public function test(): array {
                return $this->postData(['a', 'b']);
            }
        };

        $ctrl->request = new Request(method: 'POST', path: '/', post: ['a' => '1']);
        $this->assertSame(['a' => '1', 'b' => null], $ctrl->test());
    }

    public function testRenderInjectsData(): void {
        $_SESSION['_flash_messages'] = [['type' => 'info', 'text' => 'hello']];

        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->render('controller.php', ['message' => 'M']);
            }
        };

        $ctrl->request = new Request(method: 'GET', path: '/');
        $response = $ctrl->test();
        $this->assertSame(200, $response->status);
        $this->assertStringContainsString('<div>M</div>', $response->body);
        $this->assertStringContainsString('csrf_token', $response->body);
    }

    public function testRenderInjectsUrlHelper(): void {
        $app = new App();
        $app->setConfig('view_path', __DIR__ . '/../fixtures/templates');
        $app->get('/item/{id}', self::class, 'test', name: 'item.show');

        $ctrl = new class extends Controller {
            public function test(): Response {
                return $this->render('url_test.php');
            }
        };

        $ctrl->request = new Request(method: 'GET', path: '/');
        $response = $ctrl->test();
        $this->assertStringContainsString('/item/42', $response->body);
    }
}
