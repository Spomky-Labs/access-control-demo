<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Request;

/**
 * A voter that decides on the *circumstances* rather than on the requester, the subject or the
 * attribute — the fourth category of the ABAC vocabulary, and what AccessEnvironment carries.
 *
 * Its whole point is that the environment is filled by whoever let the call in, and each entry
 * point fills it with what it alone knows: the AccessPolicyListener puts the HTTP request and the
 * controller arguments in it, the ConsoleAccessPolicyListener the command, its input and its
 * output. So one attribute means "over HTTP" in one place and "on this server's console" in
 * another, without either caller having to say which it is.
 *
 * A policy may add keys of its own through `environment:`, which are merged over the entry point's.
 * That is how the route below labels itself without the voter having to know about routes.
 *
 * What is deliberately *not* here is anything a voter could reach on its own — the clock being the
 * obvious case, which is why DuringBusinessHoursHandler injects one instead. A rule that abstained
 * on a missing key would fail open, and no caller should be able to switch a rule off by leaving
 * something out.
 */
final class EntryPointVoter implements VoterInterface
{
    public const string ATTRIBUTE = 'FROM_TRUSTED_ENTRY_POINT';

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
        $environment = $accessRequest->environment;

        // The console: whoever ran the command already has a shell on this machine, so the entry
        // point itself is the credential.
        if (($command = $environment->get('command')) instanceof Command) {
            return AccessOutcome::grant(\sprintf('Reached from the console, running "%s".', $command->getName()));
        }

        if (($request = $environment->get('request')) instanceof Request) {
            // A key the policy added, merged over what the listener filled in.
            $area = $environment->get('area', 'unlabelled');

            if (!$request->isFromTrustedProxy() && !\in_array($request->getClientIp(), ['127.0.0.1', '::1'], true)) {
                return AccessOutcome::deny(\sprintf('Reached over HTTP from %s, which is not a trusted origin.', $request->getClientIp() ?? 'an unknown address'));
            }

            return AccessOutcome::grant(\sprintf('Reached over HTTP from the loopback address, in the "%s" area.', $area));
        }

        // No entry point filled anything in: this was asked programmatically. Abstaining rather
        // than refusing keeps the question open for whoever else may answer it.
        return AccessOutcome::abstain('No entry point filled the access environment.');
    }
}
