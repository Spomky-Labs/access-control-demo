<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Requester\RequesterProviderInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Says who is asking, in an application that has no Security to say it.
 *
 * With SecurityBundle the bridge points `access_control.requester_provider` at the token storage;
 * without it, the alias stays on the static (empty) provider, so an application has to name its
 * own — which is exactly what StandaloneKernel does. Here the identity comes from an API key
 * header; a real application would read it from wherever it keeps it.
 *
 * The rule listener runs on kernel.request, by which point the request is already on the stack.
 */
final readonly class ApiKeyRequesterProvider implements RequesterProviderInterface
{
    /**
     * The keys this demo knows, and what each one is allowed to be.
     *
     * @var array<string, list<string>>
     */
    private const KEYS = [
        'key-admin' => ['ROLE_ADMIN'],
        'key-editor' => ['ROLE_EDITOR'],
        'key-reader' => ['ROLE_READER'],
    ];

    public function __construct(
        private RequestStack $requestStack,
    ) {
    }

    public function getRequester(): ?ApiKeyRequester
    {
        $key = $this->requestStack->getCurrentRequest()?->headers->get('X-Api-Key');

        if (null === $key || !isset(self::KEYS[$key])) {
            return null;
        }

        return new ApiKeyRequester($key, self::KEYS[$key]);
    }
}
