<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\Flash;
use PFrame\Testing\FlashAssertions;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

class FlashAssertionsTest extends TestCase {
    use FlashAssertions;

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
    }

    protected function tearDown(): void {
        $_SESSION = [];
        parent::tearDown();
    }

    public function testAssertFlashFindsMessageByType(): void {
        (new Flash())->success('Record saved');
        $this->assertFlash('success', 'Record saved');
    }

    public function testAssertFlashFindsMessageByTypeOnly(): void {
        (new Flash())->error('Something failed');
        $this->assertFlash('error');
    }

    public function testAssertFlashFailsWhenNoMessages(): void {
        $this->expectException(AssertionFailedError::class);
        $this->assertFlash('success');
    }

    public function testAssertFlashFailsWhenWrongType(): void {
        (new Flash())->warning('Watch out');
        $this->expectException(AssertionFailedError::class);
        $this->assertFlash('error');
    }

    public function testAssertFlashFailsWhenWrongText(): void {
        (new Flash())->success('Saved');
        $this->expectException(AssertionFailedError::class);
        $this->assertFlash('success', 'Deleted');
    }

    public function testAssertNoFlashPassesWhenEmpty(): void {
        $this->assertNoFlash();
    }

    public function testAssertNoFlashPassesWhenTypeAbsent(): void {
        (new Flash())->success('OK');
        $this->assertNoFlash('error');
    }

    public function testAssertNoFlashFailsWhenTypePresent(): void {
        (new Flash())->error('Bad');
        $this->expectException(AssertionFailedError::class);
        $this->assertNoFlash('error');
    }

    public function testAssertNoFlashFailsWhenAnyPresent(): void {
        (new Flash())->info('Note');
        $this->expectException(AssertionFailedError::class);
        $this->assertNoFlash();
    }

    public function testMultipleFlashMessages(): void {
        $flash = new Flash();
        $flash->success('First');
        $flash->success('Second');
        $flash->error('Oops');

        $this->assertFlash('success', 'First');
        $this->assertFlash('success', 'Second');
        $this->assertFlash('error', 'Oops');
        $this->assertNoFlash('warning');
    }

    public function testMalformedFlashStorageFailsClearly(): void {
        $_SESSION['_flash_messages'] = 'invalid';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Flash session data must be an array');
        $this->assertNoFlash();
    }

    public function testMalformedFlashMessageFailsClearly(): void {
        $_SESSION['_flash_messages'] = [['type' => ['success'], 'text' => 'Saved']];

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Flash message type and text must be strings');
        $this->assertNoFlash();
    }
}
