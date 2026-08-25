<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\Requester\DelegatedRequesterInterface;
use AccessControl\Voter\RBAC\UserWithRoleInterface;

/**
 * A requester somebody else is really acting as — RFC 8693's "acting on behalf of".
 *
 * Unlike Security's switch_user (which needs a firewall and ROLE_ALLOWED_TO_SWITCH), this is
 * the component-native shape: an application states delegation directly on the requester, so
 * the actor can be anyone the app trusts, decoupled from the login mechanism.
 *
 * The point of keeping the two apart: this session is granted the *customer's* roles, not the
 * agent's — acting on behalf of someone must not silently hand them the agent's powers. What
 * the agent is still gets recorded, reachable through the actor (see Actor::of()), so a policy
 * can grant a break-glass action on "the real actor is an administrator" without ever widening
 * the customer's own role set.
 */
final readonly class OnBehalfOfSession implements DelegatedRequesterInterface, UserWithRoleInterface
{
    /**
     * @param mixed        $actor      The staff member really behind the session (a token or a user)
     * @param string       $onBehalfOf The customer this session stands for, for display
     * @param list<string> $roles      The customer's own roles — what the session is granted
     */
    public function __construct(
        private mixed $actor,
        private string $onBehalfOf,
        private array $roles = ['ROLE_USER'],
    ) {
    }

    public function getActor(): mixed
    {
        return $this->actor;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getOnBehalfOf(): string
    {
        return $this->onBehalfOf;
    }
}
