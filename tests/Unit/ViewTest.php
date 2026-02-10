<?php
declare(strict_types=1);

namespace P1\Tests\Unit;

use P1\View;
use PHPUnit\Framework\TestCase;

class ViewTest extends TestCase {
    private View $view;

    protected function setUp(): void {
        $this->view = new View(__DIR__ . '/../fixtures/templates');
    }

    public function testRenderSimple(): void {
        $html = $this->view->render('simple.php', ['name' => 'Joe']);
        $this->assertStringContainsString('Hello Joe', $html);
    }

    public function testRenderWithLayout(): void {
        $html = $this->view->render('with_layout.php', ['title' => 'Test']);
        $this->assertStringContainsString('<html>', $html);
        $this->assertStringContainsString('<title>Test</title>', $html);
        $this->assertStringContainsString('Content here', $html);
    }

    public function testVariablesEscaped(): void {
        $html = $this->view->render('simple.php', ['name' => '<script>']);
        $this->assertStringNotContainsString('<script>', $html);
    }

    public function testPartial(): void {
        $html = $this->view->render('with_partial.php', ['items' => ['a', 'b']]);
        $this->assertStringContainsString('item: a', $html);
        $this->assertStringContainsString('item: b', $html);
    }

    public function testMissingTemplateThrows(): void {
        $this->expectException(\RuntimeException::class);
        $this->view->render('missing.php');
    }

    public function testPathTraversalBlocked(): void {
        $root = sys_get_temp_dir() . '/p1_view_traversal_' . uniqid('', true);
        mkdir($root . '/base', 0777, true);
        mkdir($root . '/base_evil', 0777, true);
        file_put_contents($root . '/base/ok.php', '<?php echo "OK";');
        file_put_contents($root . '/base_evil/pwn.php', '<?php echo "PWN";');

        $view = new View($root . '/base');
        $this->assertSame('OK', $view->render('ok.php'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Template not found');
        try {
            $view->render('../base_evil/pwn.php');
        } finally {
            @unlink($root . '/base/ok.php');
            @unlink($root . '/base_evil/pwn.php');
            @rmdir($root . '/base');
            @rmdir($root . '/base_evil');
            @rmdir($root);
        }
    }
}
