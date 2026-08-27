<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\Testing\SessionAssertions;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

class SessionAssertionsTest extends TestCase {
    use SessionAssertions;

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
    }

    protected function tearDown(): void {
        $_SESSION = [];
        parent::tearDown();
    }

    public function testAssertAuthenticatedPassesWhenUserSet(): void {
        $_SESSION['user'] = ['id' => 1, 'name' => 'Joe'];
        $this->assertAuthenticated();
    }

    public function testAssertAuthenticatedFailsWhenGuest(): void {
        $this->expectException(AssertionFailedError::class);
        $this->assertAuthenticated();
    }

    public function testAssertAuthenticatedPassesForIntegerIdentifier(): void {
        $_SESSION['user'] = 42;
        $this->assertAuthenticated();
    }

    public function testAssertAuthenticatedPassesForStringIdentifier(): void {
        $_SESSION['user'] = 'user-token';
        $this->assertAuthenticated();
    }

    public function testAssertGuestPassesWhenNoUser(): void {
        $this->assertGuest();
    }

    public function testAssertGuestFailsWhenUserSet(): void {
        $_SESSION['user'] = ['id' => 1];
        $this->expectException(AssertionFailedError::class);
        $this->assertGuest();
    }

    public function testAssertSessionHasChecksKey(): void {
        $_SESSION['cart'] = [1, 2, 3];
        $this->assertSessionHas('cart');
    }

    public function testAssertSessionHasChecksKeyAndValue(): void {
        $_SESSION['locale'] = 'pl';
        $this->assertSessionHas('locale', 'pl');
    }

    public function testAssertSessionHasFailsOnMissing(): void {
        $this->expectException(AssertionFailedError::class);
        $this->assertSessionHas('missing');
    }

    public function testAssertSessionHasFailsOnWrongValue(): void {
        $_SESSION['locale'] = 'en';
        $this->expectException(AssertionFailedError::class);
        $this->assertSessionHas('locale', 'pl');
    }

    public function testAssertSessionMissingPasses(): void {
        $this->assertSessionMissing('nonexistent');
    }

    public function testAssertSessionMissingFailsWhenPresent(): void {
        $_SESSION['key'] = 'value';
        $this->expectException(AssertionFailedError::class);
        $this->assertSessionMissing('key');
    }
}
