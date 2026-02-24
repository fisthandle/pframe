<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\PFrame;

use PFrame\HttpException;
use PFrame\Response;

class ErrorTestController {
    public function throw404(): never {
        throw HttpException::notFound();
    }

    public function throw500(): never {
        throw new HttpException(500, 'Sensitive 500 message');
    }

    public function throw422(): never {
        throw new HttpException(422, 'Email is already taken');
    }

    public function throw403(): never {
        throw HttpException::forbidden('Forbidden debug details');
    }

    public function throw302(): never {
        throw new HttpException(302, 'Moved Temporarily', null, ['Location' => '/target']);
    }

    public function throwRuntime(): Response {
        throw new \RuntimeException('Runtime failure details');
    }
}
