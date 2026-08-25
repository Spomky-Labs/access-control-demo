<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use App\Model\Document;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * An application voter for the AccessControl component (not the Security one):
 * it implements the component's VoterInterface and is auto-tagged
 * "access_control.voter" thanks to autoconfiguration.
 *
 * It shows subject-aware (ABAC) authorization: the decision depends on *which*
 * document is targeted, not only on the roles the requester holds.
 */
final class DocumentVoter implements VoterInterface
{
    private const string VIEW = 'VIEW';
    private const string EDIT = 'EDIT';
    private const string PUBLISH = 'PUBLISH';

    public function supportsAttribute(mixed $attribute): bool
    {
        return \in_array($attribute, [self::VIEW, self::EDIT, self::PUBLISH], true);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return $subject instanceof Document;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        $document = $accessRequest->subject;
        $requester = $accessRequest->requester;

        if (!$document instanceof Document) {
            return AccessOutcome::abstain('The subject is not a document.');
        }

        if (!$requester instanceof TokenInterface || null === $user = $requester->getUser()) {
            return AccessOutcome::deny('An identified user is required.');
        }

        $isOwner = $user->getUserIdentifier() === $document->owner;
        $isAdmin = \in_array('ROLE_ADMIN', $requester->getRoleNames(), true);

        return match ($accessRequest->attribute) {
            // Owners read their own documents; administrators read them all.
            self::VIEW => $isOwner || $isAdmin
                ? AccessOutcome::grant($isOwner ? 'The owner may view the document.' : 'An administrator may view any document.')
                : AccessOutcome::deny('Only the owner or an administrator may view this document.'),
            // Editing is stricter: reserved to the owner, administrators included.
            self::EDIT => $isOwner
                ? AccessOutcome::grant('The owner may edit the document.')
                : AccessOutcome::deny('Only the owner may edit this document.'),
            // Publishing is granted like viewing (owner or admin). The ComplianceVoter
            // votes on the same request, so the combining strategy decides the outcome
            // for locked documents.
            self::PUBLISH => $isOwner || $isAdmin
                ? AccessOutcome::grant('The owner or an administrator may publish the document.')
                : AccessOutcome::deny('Only the owner or an administrator may publish this document.'),
            default => AccessOutcome::abstain('Unsupported attribute.'),
        };
    }
}
