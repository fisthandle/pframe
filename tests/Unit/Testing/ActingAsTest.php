<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\Testing\ActingAs;
use PHPUnit\Framework\TestCase;

class ActingAsTest extends TestCase {
    use ActingAs;

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
    }

    public function testActingAsSetsUser(): void {
        $this->actingAs(['id' => 1, 'name' => 'Joe']);
        $this->assertSame(['id' => 1, 'name' => 'Joe'], $_SESSION['user']);
    }

    public function testActingAsGuestRemovesUser(): void {
        $this->actingAs(['id' => 1, 'name' => 'Joe']);
        $this->actingAsGuest();
        $this->assertArrayNotHasKey('user', $_SESSION);
    }
}
