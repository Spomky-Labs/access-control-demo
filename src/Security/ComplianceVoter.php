<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use App\Model\Document;

/**
 * A second voter on the PUBLISH attribute, orthogonal to ownership: it vetoes the
 * publication of any locked document and abstains otherwise.
 *
 * Because two voters now answer the same PUBLISH request (this one and the
 * DocumentVoter), the *strategy* becomes observable:
 *   - permit_overrides (default): the owner's grant wins, the veto is ignored;
 *   - deny_overrides: the veto wins, no grant can override it.
 */
final class ComplianceVoter implements VoterInterface
{
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
        $document = $accessRequest->subject;

        if (!$document instanceof Document) {
            return AccessOutcome::abstain('The subject is not a document.');
        }

        return $document->locked
            ? AccessOutcome::deny('Compliance freezes locked documents.')
            : AccessOutcome::abstain('The document is not locked.');
    }
}
