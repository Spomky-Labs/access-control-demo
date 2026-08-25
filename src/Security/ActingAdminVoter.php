<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\Requester\Actor;
use AccessControl\Voter\RBAC\UserWithRoleInterface;
use AccessControl\VoterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Grants IS_ACTING_ADMIN when the *real actor* behind the requester is an administrator.
 *
 * Where IS_IMPERSONATOR only says that somebody is acting, this looks at who: it reads the
 * actor with Actor::of() — which covers both Security's SwitchUserToken and the component's
 * own DelegatedRequesterInterface — and checks that actor's roles rather than the requester's.
 * That is the "an administrator, even while impersonating" a bare role check cannot express,
 * because the requester on the wire is the impersonated (non-admin) identity.
 *
 * Being an app class that implements the component's VoterInterface, it is auto-tagged
 * access_control.voter and joins the vote like any built-in one.
 */
final readonly class ActingAdminVoter implements VoterInterface
{
    public const string ATTRIBUTE = 'IS_ACTING_ADMIN';

    public function supportsAttribute(mixed $attribute): bool
    {
        return self::ATTRIBUTE === $attribute;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $actor = Actor::of($accessRequest->requester);

        if (null === $actor) {
            return AccessOutcome::abstain('Nobody is acting for this requester.');
        }

        if (\in_array('ROLE_ADMIN', $this->rolesOf($actor), true)) {
            return AccessOutcome::grant(\sprintf('The real actor (%s) is an administrator.', $this->nameOf($actor)));
        }

        return AccessOutcome::deny(\sprintf('The real actor (%s) is not an administrator.', $this->nameOf($actor)));
    }

    /**
     * @return list<string>
     */
    private function rolesOf(mixed $actor): array
    {
        if ($actor instanceof TokenInterface) {
            return $actor->getRoleNames();
        }

        if ($actor instanceof UserWithRoleInterface || (\is_object($actor) && method_exists($actor, 'getRoles'))) {
            return array_values($actor->getRoles());
        }

        return [];
    }

    private function nameOf(mixed $actor): string
    {
        return match (true) {
            $actor instanceof TokenInterface => $actor->getUserIdentifier(),
            $actor instanceof UserInterface => $actor->getUserIdentifier(),
            default => 'the actor',
        };
    }
}
