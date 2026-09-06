<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

use Closure;

/**
 * Laravel / Symfony HttpFoundation middleware.
 *
 *   // bootstrap/app.php (Laravel 11+)
 *   ->withMiddleware(fn ($m) => $m->prepend(\Profullstack\X402Gateway\LaravelMiddleware::class))
 *   // and bind the gateway: $this->app->singleton(Gateway::class, fn () => new Gateway([...]));
 */
final class LaravelMiddleware
{
    public function __construct(private readonly Gateway $gateway)
    {
    }

    public function handle(object $request, Closure $next): mixed
    {
        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[strtolower((string) $name)] = implode(', ', (array) $values);
        }
        $answer = $this->gateway->handle(new Request($request->getUri(), $headers, $request->getMethod()));
        if ($answer === null) {
            return $next($request);
        }
        $class = '\Symfony\Component\HttpFoundation\Response';
        return new $class($answer->body, $answer->status, $answer->headers);
    }
}
