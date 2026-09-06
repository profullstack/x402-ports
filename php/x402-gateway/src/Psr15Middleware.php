<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware: Slim, Mezzio, Laminas, anything that takes a MiddlewareInterface.
 * Needs psr/http-server-middleware and a PSR-17 response factory (Slim's, nyholm/psr7, laminas-diactoros...).
 *
 *   $app->add(new Psr15Middleware($gateway, $app->getResponseFactory()));
 */
final class Psr15Middleware implements MiddlewareInterface
{
    public function __construct(private readonly Gateway $gateway, private readonly ResponseFactoryInterface $factory)
    {
    }

    public static function fromPsr(ServerRequestInterface $request): Request
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }
        return new Request((string) $request->getUri(), $headers, $request->getMethod());
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $answer = $this->gateway->handle(self::fromPsr($request));
        if ($answer === null) {
            return $handler->handle($request);
        }
        $response = $this->factory->createResponse($answer->status);
        foreach ($answer->headers as $k => $v) {
            $response = $response->withHeader($k, $v);
        }
        $response->getBody()->write($answer->body);
        return $response;
    }
}
