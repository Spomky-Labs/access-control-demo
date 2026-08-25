<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessRequest;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\All;
use AccessControl\Attribute\Argument;
use App\Model\Document;
use App\Security\AccessAuditSubscriber;
use App\Security\Attribute\DuringBusinessHours;
use App\Security\EntryPointVoter;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The shapes a policy can take, beyond the plain #[AccessPolicy] the rest of the app uses.
 *
 * Three things are shown here that nothing else in this application exercises: a composite the
 * component does not ship, the All composite, and what happens when every voter abstains.
 */
#[Route('/policies')]
final class PolicyController extends AbstractController
{
    /**
     * An attribute no voter in this application claims. Asking for it is how an abstention is
     * produced on purpose.
     */
    public const string UNCLAIMED = 'NOBODY_CLAIMS_THIS';

    #[Route('', name: 'app_policies')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function index(): Response
    {
        return $this->render('policy/index.html.twig', ['unclaimed' => self::UNCLAIMED]);
    }

    /**
     * A composite of the application's own, read by DuringBusinessHoursHandler.
     *
     * Outside the window it refuses, and refuses everyone: an administrator is turned away exactly
     * as a stranger is, because the window is not about who is asking. That is what makes it
     * different from #[When], whose condition failing makes it abstain and lets something else
     * grant instead.
     */
    #[Route('/business-hours', name: 'app_policy_business_hours')]
    #[DuringBusinessHours(
        [new AccessPolicy('ROLE_MANAGER')],
        from: 9,
        to: 18,
        message: 'Payroll is reachable during business hours only.',
    )]
    public function businessHours(): Response
    {
        return $this->render('policy/business_hours.html.twig');
    }

    /**
     * All grants only if every nested policy does, and refuses as soon as one refuses.
     *
     * Both halves are needed here and neither implies the other: an administrator reaches
     * ROLE_MANAGER through the hierarchy but does not own the document, and its owner may well not
     * be a manager. The pair is the point — AtLeastOneOf on the same two policies would let either
     * one through, which is what /playground/either shows.
     */
    #[Route('/both/{id<\d+>}', name: 'app_policy_both')]
    #[All(
        [
            new AccessPolicy('ROLE_MANAGER'),
            new AccessPolicy('EDIT', subject: new Argument('document')),
        ],
        message: 'Archiving takes a manager who is also the owner.',
    )]
    public function both(Document $document): Response
    {
        return $this->render('policy/both.html.twig', ['document' => $document]);
    }

    /**
     * Nobody claims the attribute, so every voter abstains — and the policy says what to make of
     * that. Declared here, it overrides the manager's own default for this request alone.
     */
    #[Route('/abstain', name: 'app_policy_abstain')]
    #[AccessPolicy(self::UNCLAIMED, allowIfAllAbstain: true, message: 'Unreachable: silence is taken as consent here.')]
    public function abstain(Security $security, AccessControlManagerInterface $manager): Response
    {
        $token = $security->getToken();

        // The same question put both ways, so the page shows the two readings side by side rather
        // than only the one that let it render.
        $lenient = $manager->decide(new AccessRequest($token, self::UNCLAIMED, allowIfAllAbstain: true));
        $strict = $manager->decide(new AccessRequest($token, self::UNCLAIMED, allowIfAllAbstain: false));

        return $this->render('policy/abstain.html.twig', [
            'unclaimed' => self::UNCLAIMED,
            'lenient' => $lenient,
            'strict' => $strict,
        ]);
    }

    /**
     * The very same attribute, with the manager's default left alone. This application's default
     * is to refuse, so the page is unreachable — which is the point of it.
     */
    #[Route('/abstain-strict', name: 'app_policy_abstain_strict')]
    #[AccessPolicy(self::UNCLAIMED, message: 'No voter claimed the attribute, and silence is not consent.')]
    public function abstainStrict(): Response
    {
        return new Response('unreachable');
    }

    /**
     * The access *environment* — the circumstances of the call, which belong neither to the
     * requester, nor to the subject, nor to the attribute.
     *
     * The listener that let this request in filled it with the HTTP request and the controller
     * arguments; `environment:` below adds a key of the policy's own on top. The same attribute on
     * a command finds the command, its input and its output there instead, and EntryPointVoter
     * reads whichever it is given.
     */
    #[Route('/entry-point', name: 'app_policy_entry_point')]
    #[AccessPolicy(
        EntryPointVoter::ATTRIBUTE,
        environment: ['area' => 'policies'],
        message: 'This page is reachable from the loopback address only.',
    )]
    public function entryPoint(AccessInspector $inspector, AccessAuditSubscriber $audit): Response
    {
        // Asked again, programmatically: nothing filled the environment this time, so the very
        // same voter abstains rather than granting.
        $programmatic = $inspector->decide(EntryPointVoter::ATTRIBUTE);

        // What the policy above was told, read back off the audit trail. The environment reaches
        // the voter and nothing else, so its reason is the only place the merged keys show up.
        $granted = null;
        foreach ($audit->getDecisions() as $decision) {
            if (EntryPointVoter::ATTRIBUTE === $decision['attribute'] && null === $granted) {
                $granted = $decision['reason'];
            }
        }

        return $this->render('policy/entry_point.html.twig', [
            'attribute' => EntryPointVoter::ATTRIBUTE,
            'programmatic' => $programmatic,
            'granted' => $granted,
        ]);
    }

    /**
     * What the component decided while rendering this very page, read off the events it dispatches.
     *
     * The trail is the application's own subscriber rather than the bundle's debug logger, which is
     * not there in production — and the page is deliberately guarded, so there is at least one
     * decision in it before the first line is rendered.
     */
    #[Route('/audit', name: 'app_policy_audit')]
    #[AccessPolicy('ROLE_USER', message: 'Sign in to read the audit trail.')]
    public function audit(AccessAuditSubscriber $audit, AccessInspector $inspector): Response
    {
        // A handful of questions, so the trail has something to show. The expression is the
        // interesting one: is_granted() inside it is a decision of its own, recorded as a child.
        $inspector->isGranted('ROLE_ADMIN');
        $inspector->isGranted(new Expression("is_granted('ROLE_MANAGER') or is_granted('ROLE_ADMIN')"));

        return $this->render('policy/audit.html.twig', [
            'decisions' => $audit->getDecisions(),
            'votes' => $audit->getVotes(),
            'queries' => $audit->getQueryCount(),
            'refusals' => \count($audit->getRefusals()),
        ]);
    }
}
