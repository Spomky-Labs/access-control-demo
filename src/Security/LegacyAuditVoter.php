<?php

declare(strict_types=1);

namespace App\Security;

use App\Model\Document;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * A voter of *Security*, not of this component — the one thing an application migrating already
 * has, probably a dozen of them, and cannot be asked to rewrite in the same commit.
 *
 * It extends Security's Voter and is tagged `security.voter` by autoconfiguration, exactly as it
 * was before this bundle existed. The bridge wraps each one in a VoterAdapter and hands it to the
 * component, so it keeps voting on the very same attributes, next to the component's own voters and
 * combined by the same strategy.
 *
 * Nothing here knows about AccessControl, and that is the point: this file is what an application
 * looks like the day before the bundle is registered, and it is unchanged the day after.
 *
 * @extends Voter<string, Document>
 */
final class LegacyAuditVoter extends Voter
{
    public const string AUDIT = 'AUDIT';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return self::AUDIT === $attribute && $subject instanceof Document;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token, ?Vote $vote = null): bool
    {
        \assert($subject instanceof Document);

        // Locked documents are the ones worth auditing, and only a manager may.
        if (!$subject->locked) {
            $vote?->addReason('The document is not locked, so there is nothing to audit.');

            return false;
        }

        if (!\in_array('ROLE_MANAGER', $token->getRoleNames(), true)) {
            $vote?->addReason('Auditing a locked document takes a manager.');

            return false;
        }

        $vote?->addReason('A manager may audit a locked document.');

        return true;
    }
}
