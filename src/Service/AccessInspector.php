<?php

declare(strict_types=1);

namespace App\Service;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use Symfony\Bundle\SecurityBundle\Security;

/**
 * A thin, reusable wrapper around the AccessControl services, used programmatically
 * (no #[AccessPolicy] attribute in sight).
 *
 * It injects the component's own `AccessControlManagerInterface` and builds an
 * AccessRequest around the current requester (the security token, resolved by
 * SecurityBundle's Security helper — which works both on the web and, once a token
 * has been placed in storage, on the console).
 *
 * decide() returns the full AccessDecision (verdict, reason, individual votes), which
 * is what makes the programmatic path richer than a bare yes/no.
 */
final readonly class AccessInspector
{
    public function __construct(
        private AccessControlManagerInterface $accessControlManager,
        private Security $security,
    ) {
    }

    public function decide(mixed $attribute, mixed $subject = null, ?string $strategy = null): AccessDecision
    {
        return $this->accessControlManager->decide(
            new AccessRequest($this->security->getToken(), $attribute, $subject),
            $strategy,
        );
    }

    public function isGranted(mixed $attribute, mixed $subject = null, ?string $strategy = null): bool
    {
        return DecisionVote::ACCESS_GRANTED === $this->decide($attribute, $subject, $strategy)->decision;
    }

    /**
     * Decide for an explicit requester rather than the current token. Naming its own requester
     * is native to the component — an AccessRequest carries it — where Security needs a dedicated
     * contract. This is what lets the app ask about a delegated session (see OnBehalfOfSession).
     */
    public function decideFor(mixed $requester, mixed $attribute, mixed $subject = null, ?string $strategy = null): AccessDecision
    {
        return $this->accessControlManager->decide(new AccessRequest($requester, $attribute, $subject), $strategy);
    }

    public function isGrantedFor(mixed $requester, mixed $attribute, mixed $subject = null, ?string $strategy = null): bool
    {
        return DecisionVote::ACCESS_GRANTED === $this->decideFor($requester, $attribute, $subject, $strategy)->decision;
    }
}
