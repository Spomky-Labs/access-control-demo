<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A voter of the AccessControl component alone — it is tagged `access_control.voter` and is not,
 * and cannot be, a Security voter.
 *
 * That is what makes it a probe: Security's access listener would never consult it, so if a rule
 * declared under `security.access_control` is decided by this voter, the rule is being enforced by
 * the component rather than by the firewall.
 */
final class VaultVoter implements VoterInterface
{
    public const string ROLE = 'ROLE_VAULT';

    public function supportsAttribute(mixed $attribute): bool
    {
        return self::ROLE === $attribute;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        // A rule built from security.access_control names the request as its subject, exactly as
        // the component's own key does.
        $request = $accessRequest->subject;

        if (!$request instanceof Request) {
            return AccessOutcome::abstain('The subject is not a request.');
        }

        if ('open-sesame' === $request->headers->get('X-Vault-Token')) {
            return AccessOutcome::grant('The vault token is valid.');
        }

        return AccessOutcome::abstain('No vault token on the request.');
    }
}
