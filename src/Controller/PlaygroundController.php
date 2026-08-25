<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessRequest;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\DecisionVote;
use AccessControl\Requester\Actor;
use AccessControl\RequesterBoundChecker;
use App\Security\ActingAdminVoter;
use App\Security\OnBehalfOfSession;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

#[Route('/playground')]
final class PlaygroundController extends AbstractController
{
    #[Route('', name: 'app_playground')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function index(): Response
    {
        return $this->render('playground/index.html.twig');
    }

    /**
     * AtLeastOneOf grants as soon as one nested policy grants: here, holding either
     * ROLE_ADMIN or ROLE_MANAGER is enough. A plain ROLE_USER is refused.
     */
    #[Route('/either', name: 'app_playground_either')]
    #[AtLeastOneOf([new AccessPolicy('ROLE_ADMIN'), new AccessPolicy('ROLE_MANAGER')], message: 'Managers or administrators only.')]
    public function either(): Response
    {
        return $this->render('playground/either.html.twig');
    }

    /**
     * The ClosureVoter cannot be reached from a #[AccessPolicy] attribute — PHP
     * forbids closures in attribute arguments — so this is the programmatic path:
     * we ask the AccessControlManager directly, passing a closure as the attribute.
     *
     * Each closure receives the AccessRequest and a checker bound to its requester,
     * so it can ask further questions exactly like an expression does.
     */
    #[Route('/closure', name: 'app_playground_closure')]
    #[AccessPolicy('ROLE_USER')]
    public function closure(Security $security, AccessControlManagerInterface $manager): Response
    {
        $token = $security->getToken();

        /** @var array<string, \Closure> $rules */
        $rules = [
            'Holds ROLE_USER and is not the "guest" account' => static fn (AccessRequest $request, RequesterBoundChecker $checker): bool
                => $checker->isGranted('ROLE_USER') && 'guest' !== $request->requester?->getUser()?->getUserIdentifier(),
            'Holds both ROLE_MANAGER and ROLE_ADMIN' => static fn (AccessRequest $request, RequesterBoundChecker $checker): bool
                => $checker->isGranted('ROLE_MANAGER') && $checker->isGranted('ROLE_ADMIN'),
        ];

        $results = [];
        foreach ($rules as $label => $rule) {
            $decision = $manager->decide(new AccessRequest($token, $rule));
            $results[$label] = [
                'granted' => DecisionVote::ACCESS_GRANTED === $decision->decision,
                'reason' => $decision->reason,
            ];
        }

        return $this->render('playground/closure.html.twig', ['results' => $results]);
    }

    /**
     * Only reachable while impersonating: the AuthenticatedVoter grants IS_IMPERSONATOR
     * exactly when the token is a SwitchUserToken. Switch in with ?_switch_user=user
     * from any page (needs ROLE_ALLOWED_TO_SWITCH, granted to admin), leave with
     * ?_switch_user=_exit.
     */
    #[Route('/impersonation', name: 'app_playground_impersonation')]
    #[AccessPolicy('IS_IMPERSONATOR', message: 'This page is only reachable while impersonating another user.')]
    public function impersonation(Security $security): Response
    {
        $token = $security->getToken();

        return $this->render('playground/impersonation.html.twig', [
            'impersonated' => $token?->getUserIdentifier(),
            'impersonator' => $token instanceof SwitchUserToken ? $token->getOriginalToken()->getUserIdentifier() : null,
        ]);
    }

    /**
     * Delegation the component's own way: an application names the actor behind a requester
     * (RFC 8693), no firewall or switch_user involved. A support agent handles a customer's
     * session; the session keeps the *customer's* roles, yet the app still knows an admin is
     * really behind it.
     *
     * Decided programmatically for two explicit requesters so the contrast is visible on one
     * page — nothing here depends on who is logged in.
     */
    #[Route('/on-behalf', name: 'app_playground_on_behalf')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function onBehalf(AccessInspector $inspector): Response
    {
        // The staff member really behind the delegated session, an administrator.
        $agent = new UsernamePasswordToken(new InMemoryUser('support-agent', null, ['ROLE_ADMIN']), 'main', ['ROLE_ADMIN']);

        $scenarios = [
            [
                'title' => 'Customer alone',
                'description' => 'The customer browsing for themselves — nobody is acting behind them.',
                'requester' => new InMemoryUser('customer-42', null, ['ROLE_USER']),
            ],
            [
                'title' => 'Support agent, on behalf of the customer',
                'description' => 'An admin agent handles the very same customer session through OnBehalfOfSession.',
                'requester' => new OnBehalfOfSession($agent, 'customer-42', ['ROLE_USER']),
            ],
        ];

        // The questions asked of each requester. The first is about the session's own rights,
        // the last two about who is really acting behind it.
        $attributes = [
            'ROLE_ADMIN' => 'Is the session itself an administrator?',
            'IS_IMPERSONATOR' => 'Is somebody acting behind the session?',
            ActingAdminVoter::ATTRIBUTE => 'Is the real actor an administrator?',
        ];

        $rows = [];
        foreach ($scenarios as $scenario) {
            $actor = Actor::of($scenario['requester']);
            $checks = [];
            foreach ($attributes as $attribute => $_question) {
                $checks[$attribute] = $inspector->isGrantedFor($scenario['requester'], $attribute);
            }

            $rows[] = [
                'title' => $scenario['title'],
                'description' => $scenario['description'],
                'actor' => $actor instanceof UsernamePasswordToken ? $actor->getUserIdentifier() : null,
                'checks' => $checks,
            ];
        }

        return $this->render('playground/on_behalf.html.twig', [
            'questions' => $attributes,
            'rows' => $rows,
        ]);
    }
}
