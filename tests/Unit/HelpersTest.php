<?php
declare(strict_types=1);

namespace P1\Tests\Unit;

use PHPUnit\Framework\TestCase;

class HelpersTest extends TestCase {
    public function testHEscapesHtml(): void {
        $this->assertSame('&lt;script&gt;', h('<script>'));
        $this->assertSame('&amp;', h('&'));
        $this->assertSame('', h(null));
        $this->assertSame('', h(''));
        $this->assertSame('hello', h('hello'));
        $this->assertSame('', h(['x']));
    }

    public function testHaEscapesArrayValue(): void {
        $data = ['name' => '<b>Joe</b>', 'age' => 30];
        $this->assertSame('&lt;b&gt;Joe&lt;/b&gt;', ha($data, 'name'));
        $this->assertSame('30', ha($data, 'age'));
        $this->assertSame('default', ha($data, 'missing', 'default'));
        $this->assertSame('', ha($data, 'missing'));
    }

    public function testGetS(): void {
        $data = ['key' => 'val'];
        $this->assertSame('val', getS($data, 'key'));
        $this->assertNull(getS($data, 'missing'));
        $this->assertSame('def', getS($data, 'missing', 'def'));
        $this->assertNull(getS(null, 'key'));
    }

    public function testMbStrlenS(): void {
        $this->assertSame(0, mb_strlenS(null));
        $this->assertSame(5, mb_strlenS('hello'));
        $this->assertSame(4, mb_strlenS('żółw'));
    }

    public function testMbSubstrS(): void {
        $this->assertSame('llo', mb_substrS('hello', 2));
        $this->assertSame('żó', mb_substrS('żółw', 0, 2));
        $this->assertSame('', mb_substrS(null, 0));
    }

    public function testTrimS(): void {
        $this->assertSame('hello', trimS('  hello  '));
        $this->assertSame('', trimS(null));
        $this->assertSame('42', trimS(42));
        $this->assertSame('hello', trimS('xxxhelloxxx', 'x'));
    }

    public function testStrtotimeS(): void {
        $this->assertIsInt(strtotimeS('2024-01-01'));
        $this->assertFalse(strtotimeS(null));
        $this->assertFalse(strtotimeS(''));
    }

    public function testStripTagsS(): void {
        $this->assertSame('hello', strip_tagsS('<b>hello</b>'));
        $this->assertSame('', strip_tagsS(null));
    }

    public function testCountS(): void {
        $this->assertSame(0, countS(null));
        $this->assertSame(2, countS([1, 2]));
        $this->assertSame(0, countS('string'));
        $this->assertSame(0, countS(42));
        $this->assertSame(1, countS(new class implements \Countable {
            public function count(): int {
                return 1;
            }
        }));
    }

    public function testExplodeS(): void {
        $this->assertSame(['a', 'b', 'c'], explodeS(',', 'a, b, c'));
        $this->assertSame([], explodeS(',', null));
        $this->assertSame([], explodeS(',', ''));
        $this->assertSame(['a', 'b,c'], explodeS(',', 'a,b,c', 2));
        $this->assertSame(['123'], explodeS(',', 123));
        $this->assertSame([], explodeS(',', new \stdClass()));
    }
}
