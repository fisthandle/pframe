<?php
declare(strict_types=1);

namespace P1\Tests\Unit;

use P1\Response;
use PHPUnit\Framework\TestCase;

class ResponseTest extends TestCase {
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
        try {
            Response::redirect('https://evil.com/phish');
        } finally {
            $_SERVER = [];
        }
    }

    public function testRedirectAllowsSameHost(): void {
        $_SERVER['HTTP_HOST'] = 'myapp.com';
        $r = Response::redirect('https://myapp.com/dashboard');
        $this->assertSame('https://myapp.com/dashboard', $r->headers['Location']);
        $_SERVER = [];
    }

    public function testRedirectAllowsRelativePath(): void {
        $r = Response::redirect('/login');
        $this->assertSame('/login', $r->headers['Location']);
    }
}
