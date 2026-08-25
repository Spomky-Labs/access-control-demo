<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Requester\RequesterProviderInterface;

/**
 * A requester provider a test can set, which is what the token storage is to an application that
 * has Security: something outside the decision path decides who is asking, and the component reads
 * it when a question is put.
 *
 * A workflow transition is not an HTTP request, so there is no header to read it from — the
 * counterpart of this in a real application would be a service account, a message envelope stamp,
 * or whatever that application already knows.
 */
final class MutableRequesterProvider implements RequesterProviderInterface
{
    private mixed $requester = null;

    public function setRequester(mixed $requester): void
    {
        $this->requester = $requester;
    }

    public function getRequester(): mixed
    {
        return $this->requester;
    }
}
