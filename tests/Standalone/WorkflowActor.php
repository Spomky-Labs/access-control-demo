<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Voter\RBAC\UserWithRoleInterface;

/**
 * Who is asking, in the shape of the application that has no Security.
 *
 * getUserIdentifier() is not required by the component — the RoleVoter reads getRoles() alone —
 * but InMemoryUser carries the same method, so a guard naming `user.getUserIdentifier()` reads
 * identically under both shapes. That is what lets one workflow configuration be measured with
 * Security and without it.
 *
 * The call is written out because ExpressionLanguage reads a property where PropertyAccess would
 * have looked for a getter: `user.userIdentifier` is null here, and silently so.
 */
final readonly class WorkflowActor implements UserWithRoleInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        private string $identifier,
        private array $roles,
    ) {
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }
}
