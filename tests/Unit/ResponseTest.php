<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Response;
use PHPUnit\Framework\TestCase;

class ResponseTest extends TestCase {
    private array $serverSnapshot;

    protected function setUp(): void {
        $this->serverSnapshot = $_SERVER;
        $_SERVER = [];
    }

    protected function tearDown(): void {
        $_SERVER = $this->serverSnapshot;
    }

    public function testDefaults(): void {
        $r = new Response('Hello');
        $this->assertSame(200, $r->status);
        $this->assertSame('Hello', $r->body);
    }

    public function testJson(): void {
        $r = Response::json(['ok' => true], 201);
        $this->assertSame(201, $r->status);
        $this->assertSame('application/json', $r->headers['Content-Type']);
        $this->assertSame('{"ok":true}', $r->body);
    }

    public function testRedirect(): void {
        $r = Response::redirect('/login');
        $this->assertSame(302, $r->status);
        $this->assertSame('/login', $r->headers['Location']);
    }

    public function testHtml(): void {
        $r = Response::html('<h1>Hi</h1>');
        $this->assertSame('text/html; charset=UTF-8', $r->headers['Content-Type']);
    }

    public function testRedirectBlocksExternalUrl(): void {
        $_SERVER['HTTP_HOST'] = 'myapp.com';
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('https://evil.com/phish');
    }

    public function testRedirectAllowsSameHost(): void {
        $_SERVER['HTTP_HOST'] = 'myapp.com';
        $r = Response::redirect('https://myapp.com/dashboard');
        $this->assertSame('https://myapp.com/dashboard', $r->headers['Location']);
    }

    public function testRedirectAllowsRelativePath(): void {
        $r = Response::redirect('/login');
        $this->assertSame('/login', $r->headers['Location']);
    }

    public function testRedirectBlocksExternalUrlWithoutHost(): void {
        $this->expectException(\InvalidArgumentException::class);
        Response::redirect('https://evil.com/phish');
    }

    public function testRedirectBlocksSchemeRelativeUrl(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('//evil.com/phish');
    }

    public function testRedirectBlocksBackslashProtocolRelative(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('/\\evil.com');
    }

    public function testRedirectBlocksBackslashInPath(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('/foo\\bar');
    }

    public function testRedirectBlocksHttpSchemeWithoutAuthority(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('http:evil.com');
    }

    public function testRedirectBlocksJavascriptScheme(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('javascript:alert(1)');
    }

    public function testRedirectBlocksDataScheme(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('data:text/html,<script>alert(1)</script>');
    }

    public function testRedirectBlocksJavascriptSchemeUppercase(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect('JaVaScRiPt:alert(1)');
    }

    public function testRedirectBlocksWhitespaceSchemeBypass(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect(' javascript:alert(1)');
    }

    public function testRedirectBlocksTabSchemeBypass(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('External redirect not allowed');
        Response::redirect("\tjavascript:alert(1)");
    }

    public function testRedirectAllowsQueryStringWithoutSlash(): void {
        $r = Response::redirect('?page=2');
        $this->assertSame('?page=2', $r->headers['Location']);
    }

    public function testSendAndExitMethodContract(): void {
        $method = new \ReflectionMethod(Response::class, 'sendAndExit');
        $this->assertTrue($method->hasReturnType());
        $this->assertSame('never', (string) $method->getReturnType());
    }

    public function testFileFactoryCreatesResponseWithFilePath(): void {
        $response = Response::file('/tmp/test.txt', ['Content-Type' => 'text/plain']);
        $this->assertSame(200, $response->status);
        $this->assertSame('/tmp/test.txt', $response->filePath);
        $this->assertSame('text/plain', $response->headers['Content-Type']);
        $this->assertSame('', $response->body);
    }

    public function testFileFactoryWithCustomStatus(): void {
        $response = Response::file('/tmp/test.txt', [], 206);
        $this->assertSame(206, $response->status);
    }

    public function testFileSendOutputsFileContent(): void {
        $tmpFile = tempnam(sys_get_temp_dir(), 'pframe_test_');
        $this->assertNotFalse($tmpFile);
        file_put_contents($tmpFile, 'file content here');

        $response = Response::file($tmpFile);
        ob_start();
        $response->send();
        $output = (string) ob_get_clean();
        $this->assertSame('file content here', $output);

        unlink($tmpFile);
    }

    public function testSendOutputsBodyAndSetsStatusWithHeaders(): void {
        $response = new Response('hello body', 201, ['X-Test' => 'yes']);

        ob_start();
        $response->send();
        $output = (string) ob_get_clean();

        $this->assertSame('hello body', $output);
        $this->assertSame(201, http_response_code());
    }
}
