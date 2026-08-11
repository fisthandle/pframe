<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Validator;
use PHPUnit\Framework\TestCase;

class ValidatorTest extends TestCase {
    public function testEmail(): void {
        $this->assertTrue(Validator::email('a@b.com'));
        $this->assertFalse(Validator::email('notanemail'));
    }

    public function testPhone(): void {
        $this->assertTrue(Validator::phone('123456789'));
        $this->assertTrue(Validator::phone('+48 123 456 789'));
        $this->assertFalse(Validator::phone('12345'));
    }

    public function testPostcode(): void {
        $this->assertTrue(Validator::postcode('30-002'));
        $this->assertFalse(Validator::postcode('3002'));
    }

    public function testLength(): void {
        $this->assertNull(Validator::length('hello', 3, 10));
        $this->assertNotNull(Validator::length('hi', 3, 10));
        $this->assertNotNull(Validator::length('very long text', 1, 4));
    }

    public function testRequired(): void {
        $this->assertTrue(Validator::required('x'));
        $this->assertFalse(Validator::required(''));
        $this->assertFalse(Validator::required(null));
        $this->assertFalse(Validator::required([]));
    }

    public function testIntRange(): void {
        $this->assertTrue(Validator::intRange(5, 1, 10));
        $this->assertTrue(Validator::intRange('5', 1, 10));
        $this->assertFalse(Validator::intRange(11, 1, 10));
        $this->assertFalse(Validator::intRange('abc', 1, 10));
        $this->assertFalse(Validator::intRange(1.9, 1, 10));
        $this->assertFalse(Validator::intRange('1e1', 1, 10));
        $this->assertFalse(Validator::intRange(true, 1, 10));
    }

    public function testSlug(): void {
        $this->assertNull(Validator::slug('valid-slug'));
        $this->assertNotNull(Validator::slug('Invalid'));
        $this->assertNotNull(Validator::slug(str_repeat('a', 101)));
    }

    public function testValidateMap(): void {
        $rules = [
            'email' => ['required', 'email'],
            'phone' => ['phone'],
            'postcode' => ['postcode'],
        ];

        $errors = Validator::validate($rules, [
            'email' => 'bad',
            'phone' => '12345',
            'postcode' => '30-002',
        ]);

        $this->assertSame('Nieprawidłowy email', $errors['email']);
        $this->assertSame('Nieprawidłowy telefon', $errors['phone']);
        $this->assertArrayNotHasKey('postcode', $errors);

        $errors = Validator::validate(['x' => ['required']], ['x' => '']);
        $this->assertSame('Pole wymagane', $errors['x']);

        $errors = Validator::validate(['email' => ['email']], ['email' => ['attacker-controlled-array']]);
        $this->assertSame('Nieprawidłowy email', $errors['email']);
    }
}
