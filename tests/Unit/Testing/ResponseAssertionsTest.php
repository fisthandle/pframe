<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\Response;
use PFrame\Testing\ResponseAssertions;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

class ResponseAssertionsTest extends TestCase {
    use ResponseAssertions;

    public function testAssertStatusPassesOnMatch(): void {
        $this->response = new Response('', 201);
        $this->assertStatus(201);
    }

    public function testAssertStatusFailsOnMismatch(): void {
        $this->response = new Response('', 404);
        $this->expectException(AssertionFailedError::class);
        $this->assertStatus(200);
    }

    public function testAssertOk(): void {
        $this->response = new Response('OK', 200);
        $this->assertOk();
    }

    public function testAssertNotFound(): void {
        $this->response = new Response('', 404);
        $this->assertNotFound();
    }

    public function testAssertForbidden(): void {
        $this->response = new Response('', 403);
        $this->assertForbidden();
    }

    public function testAssertUnauthorized(): void {
        $this->response = new Response('', 401);
        $this->assertUnauthorized();
    }

    public function testAssertRedirectPassesOn302(): void {
        $this->response = new Response('', 302, ['Location' => '/dashboard']);
        $this->assertRedirect();
    }

    public function testAssertRedirectPassesOn301(): void {
        $this->response = new Response('', 301, ['Location' => '/new-url']);
        $this->assertRedirect();
    }

    public function testAssertRedirectToPassesOnMatchingUrl(): void {
        $this->response = new Response('', 302, ['Location' => '/login']);
        $this->assertRedirectTo('/login');
    }

    public function testAssertRedirectToFailsOnWrongUrl(): void {
        $this->response = new Response('', 302, ['Location' => '/dashboard']);
        $this->expectException(AssertionFailedError::class);
        $this->assertRedirectTo('/login');
    }

    public function testAssertSeeFindsTextInBody(): void {
        $this->response = new Response('<h1>Welcome back</h1>');
        $this->assertSee('Welcome');
    }

    public function testAssertSeeFailsWhenTextMissing(): void {
        $this->response = new Response('<h1>Hello</h1>');
        $this->expectException(AssertionFailedError::class);
        $this->assertSee('Goodbye');
    }

    public function testAssertDontSeePassesWhenTextMissing(): void {
        $this->response = new Response('<h1>Hello</h1>');
        $this->assertDontSee('Goodbye');
    }

    public function testAssertDontSeeFailsWhenTextPresent(): void {
        $this->response = new Response('<h1>Hello</h1>');
        $this->expectException(AssertionFailedError::class);
        $this->assertDontSee('Hello');
    }

    public function testAssertJsonPassesOnValidJson(): void {
        $this->response = Response::json(['success' => true, 'count' => 3]);
        $this->assertJsonContains(['success' => true]);
    }

    public function testAssertJsonChecksSubset(): void {
        $this->response = Response::json(['a' => 1, 'b' => 2, 'c' => 3]);
        $this->assertJsonContains(['a' => 1, 'c' => 3]);
    }

    public function testAssertJsonFailsOnMismatch(): void {
        $this->response = Response::json(['success' => false]);
        $this->expectException(AssertionFailedError::class);
        $this->assertJsonContains(['success' => true]);
    }

    public function testAssertJsonFailsWhenBodyIsNotAnObject(): void {
        $this->response = Response::json('scalar');
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Response body is not a JSON object');
        $this->assertJsonContains(['success' => true]);
    }

    public function testAssertJsonRejectsListEvenForEmptySubset(): void {
        $this->response = Response::json([['id' => 1]]);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Response body is not a JSON object');
        $this->assertJsonContains([]);
    }

    public function testAssertHeaderPassesOnMatch(): void {
        $this->response = new Response('', 200, ['Content-Type' => 'application/json']);
        $this->assertHeader('Content-Type', 'application/json');
    }

    public function testAssertHeaderExistsWithoutValueCheck(): void {
        $this->response = new Response('', 200, ['X-Custom' => 'anything']);
        $this->assertHeader('X-Custom');
    }

    public function testAssertHeaderMissing(): void {
        $this->response = new Response('', 200, []);
        $this->assertHeaderMissing('X-Custom');
    }
}
