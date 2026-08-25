<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Voter\RBAC\RoleHierarchyInterface;
use AccessControl\Voter\RBAC\UserWithRoleInterface;
use AccessControl\VoterInterface;
use App\Model\Document;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * The third voter on PUBLISH, and the one that makes a quorum possible: the editorial board signs
 * off on a publication regardless of who owns the document.
 *
 * With only DocumentVoter and ComplianceVoter, PUBLISH could never gather two grants, so the
 * two-key rule would have been a refusal dressed up as a strategy. Here an owner who is also on the
 * board turns both keys at once.
 *
 * It reads the roles through the hierarchy rather than off the token, so ROLE_ADMIN reaches the
 * board exactly as it reaches ROLE_MANAGER anywhere else.
 */
final readonly class EditorialBoardVoter implements VoterInterface
{
    public const string ROLE = 'ROLE_MANAGER';

    public function __construct(
        private RoleHierarchyInterface $roleHierarchy,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return 'PUBLISH' === $attribute;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return $subject instanceof Document;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $roles = $this->rolesOf($accessRequest->requester);

        if (\in_array(self::ROLE, $this->roleHierarchy->getReachableRoleNames($roles), true)) {
            return AccessOutcome::grant('The editorial board signs off on the publication.');
        }

        // Abstain rather than deny: not being on the board is not an objection to publishing, and
        // a denial here would make the board a veto it is not.
        return AccessOutcome::abstain('The requester is not on the editorial board.');
    }

    /**
     * @return list<string>
     */
    private function rolesOf(mixed $requester): array
    {
        return match (true) {
            $requester instanceof TokenInterface => $requester->getRoleNames(),
            $requester instanceof UserWithRoleInterface => $requester->getRoles(),
            default => [],
        };
    }
}
