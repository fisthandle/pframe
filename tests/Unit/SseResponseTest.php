<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\Response;
use PFrame\SseResponse;
use PHPUnit\Framework\TestCase;

class SseResponseTest extends TestCase {
    public function testSseResponseHasCorrectHeaders(): void {
        $response = new SseResponse(function (): void {
        });

        $this->assertSame(200, $response->status);
        $this->assertSame('text/event-stream', $response->headers['Content-Type']);
        $this->assertSame('no-cache', $response->headers['Cache-Control']);
        $this->assertSame('keep-alive', $response->headers['Connection']);
        $this->assertSame('no', $response->headers['X-Accel-Buffering']);
    }

    public function testSseResponseIsInstanceOfResponse(): void {
        $response = new SseResponse(function (): void {
        });
        $this->assertInstanceOf(Response::class, $response);
    }

    public function testConstructorRejectsNonClosureCallback(): void {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('SseResponse requires callback closure');

        new SseResponse('not-a-callback');
    }

    public function testInheritedResponseFactoriesAreRejected(): void {
        $factories = [
            'json' => static fn(): SseResponse => SseResponse::json(['ok' => true]),
            'html' => static fn(): SseResponse => SseResponse::html('<p>no</p>'),
            'file' => static fn(): SseResponse => SseResponse::file('/tmp/no'),
            'redirect' => static fn(): SseResponse => SseResponse::redirect('/no'),
        ];

        foreach ($factories as $name => $factory) {
            try {
                $factory();
                $this->fail("SseResponse::$name() should be rejected");
            } catch (\LogicException $e) {
                $this->assertStringContainsString("does not support $name()", $e->getMessage());
            }
        }
    }

    public function testSendRunsCallback(): void {
        $called = false;
        $response = new SseResponse(function () use (&$called): void {
            $called = true;
            echo "event: ping\\n";
            echo "data: ok\\n\\n";
        });

        ob_start();
        $response->send();
        $output = (string) ob_get_clean();

        $this->assertTrue($called);
        $this->assertStringContainsString('event: ping', $output);
        $this->assertStringContainsString('data: ok', $output);
    }

    public function testRunClosesFailedStreamWithoutHtmlFallback(): void {
        $server = $_SERVER;
        $_SERVER = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/stream'];
        $app = new App();
        $app->get('/stream', FailedSseController::class, 'stream');

        ob_start();
        try {
            $app->run();
        } finally {
            $output = (string) ob_get_clean();
            $_SERVER = $server;
        }

        $this->assertSame("event: ready\n\n", $output);
        $this->assertStringNotContainsString('<html', strtolower($output));
    }
}

class FailedSseController {
    public function stream(): SseResponse {
        return new SseResponse(static function (): void {
            echo "event: ready\n\n";
            throw new \RuntimeException('stream failed');
        });
    }
}
