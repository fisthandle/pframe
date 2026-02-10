<?php
declare(strict_types=1);

namespace P1\Tests\Unit;

use P1\Request;
use PHPUnit\Framework\TestCase;

class RequestTest extends TestCase {
    protected function tearDown(): void {
        $_SERVER = [];
        $_GET = [];
        $_POST = [];
        $_COOKIE = [];
        $_FILES = [];
    }

    public function testFromGlobals(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/test?foo=bar';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest';
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        $_GET = ['foo' => 'bar'];
        $_POST = [];

        $req = Request::fromGlobals();

        $this->assertSame('GET', $req->method);
        $this->assertSame('/test', $req->path);
        $this->assertSame('bar', $req->query('foo'));
        $this->assertSame('127.0.0.1', $req->ip);
        $this->assertSame('application/json', $req->header('content-type'));
        $this->assertTrue($req->isAjax());
    }

    public function testFromGlobalsTrustedProxiesUsesForwardedFor(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5, 10.0.0.1';

        $req = Request::fromGlobalsWithProxies(['10.0.0.1']);
        $this->assertSame('203.0.113.5', $req->ip);
    }

    public function testFromGlobalsUntrustedProxyIgnoresForwardedFor(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['REMOTE_ADDR'] = '198.51.100.10';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';

        $req = Request::fromGlobalsWithProxies(['10.0.0.1']);
        $this->assertSame('198.51.100.10', $req->ip);
    }

    public function testFromGlobalsTrustedProxySkipsInvalidForwardedFor(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = 'bad-ip, 203.0.113.10';

        $req = Request::fromGlobalsWithProxies(['10.0.0.1']);
        $this->assertSame('203.0.113.10', $req->ip);
    }

    public function testFromGlobalsTrustedProxyInvalidRealIpFallsBack(): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        $_SERVER['HTTP_X_REAL_IP'] = 'bad-ip';

        $req = Request::fromGlobalsWithProxies(['10.0.0.1']);
        $this->assertSame('10.0.0.1', $req->ip);
    }

    public function testManualConstruction(): void {
        $req = new Request(
            method: 'POST',
            path: '/submit',
            query: ['a' => '1'],
            post: ['name' => 'Joe'],
            headers: ['Content-Type' => 'application/json'],
            cookies: ['sid' => 'x'],
            files: ['f' => ['name' => 'a.txt']],
            ip: '10.0.0.1',
        );

        $this->assertSame('POST', $req->method);
        $this->assertSame('/submit', $req->path);
        $this->assertSame('1', $req->query('a'));
        $this->assertSame('Joe', $req->post('name'));
        $this->assertSame('application/json', $req->header('Content-Type'));
        $this->assertSame('x', $req->cookie('sid'));
        $this->assertSame('a.txt', $req->file('f')['name']);
        $this->assertTrue($req->isPost());
        $this->assertFalse($req->isAjax());
    }

    public function testParamsSetByRouter(): void {
        $req = new Request(method: 'GET', path: '/o/test-slug');
        $req->setParams(['slug' => 'test-slug']);
        $this->assertSame('test-slug', $req->param('slug'));
        $this->assertNull($req->param('missing'));
    }

    public function testOnly(): void {
        $req = new Request(method: 'POST', path: '/', post: ['a' => '1', 'b' => '2', 'c' => '3']);
        $result = $req->only(['a', 'c', 'missing']);
        $this->assertSame(['a' => '1', 'c' => '3', 'missing' => null], $result);
    }

    public function testJsonBody(): void {
        $req = new Request(method: 'POST', path: '/', body: '{"a":1}');
        $this->assertSame(['a' => 1], $req->jsonBody());

        $invalid = new Request(method: 'POST', path: '/', body: 'x');
        $this->assertNull($invalid->jsonBody());

        $empty = new Request(method: 'POST', path: '/');
        $this->assertNull($empty->jsonBody());
    }
}
