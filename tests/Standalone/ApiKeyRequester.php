<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Voter\RBAC\UserWithRoleInterface;

/**
 * A requester in an application that has no Security: no token, no user provider, no firewall.
 *
 * Implementing the component's own UserWithRoleInterface is all the RoleVoter needs to read the
 * roles, and the role hierarchy is applied on top of them exactly as it is for a Security token.
 */
final readonly class ApiKeyRequester implements UserWithRoleInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        private string $key,
        private array $roles,
    ) {
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getKey(): string
    {
        return $this->key;
    }
}
