<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use App\Model\Document;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Target;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Workflow\Exception\LogicException;
use Symfony\Component\Workflow\WorkflowInterface;

/**
 * The publication workflow of a document, and who may move it.
 *
 * Two different mechanisms guard this page, which is the point of it:
 *
 *   * #[AccessPolicy] guards the *controller* — may this requester look at the page at all;
 *   * `guard:` guards each *transition* — may this requester move this document from here.
 *
 * Both are answered by the same voters. A transition guard reaches them through Workflow's own
 * listener, which asks the authorization checker, which the bridge has pointed at this component:
 * DocumentVoter and ComplianceVoter decide a workflow transition without knowing they do.
 */
#[Route('/documents/{id<\d+>}/workflow')]
final class WorkflowController extends AbstractController
{
    public function __construct(
        #[Target('document_publication')]
        private readonly WorkflowInterface $workflow,
    ) {
    }

    /**
     * VIEW rather than EDIT: looking at where a document stands is not moving it, and each
     * transition below says for itself whether it is within reach.
     */
    #[Route('', name: 'app_document_workflow', methods: ['GET'])]
    #[AccessPolicy('VIEW', subject: new Argument('document'), message: 'You are not allowed to view this document.')]
    public function show(Document $document): Response
    {
        $transitions = [];

        foreach ($this->workflow->getDefinition()->getTransitions() as $transition) {
            $blockers = $this->workflow->buildTransitionBlockerList($document, $transition->getName());

            $reasons = [];
            foreach ($blockers as $blocker) {
                $reasons[] = $blocker->getMessage();
            }

            $transitions[] = [
                'name' => $transition->getName(),
                'from' => implode(', ', $transition->getFroms()),
                'to' => implode(', ', $transition->getTos()),
                'enabled' => $blockers->isEmpty(),
                // A transition can be out of reach for two unrelated reasons: the document is not
                // in the right place, or the guard refused. The blockers tell them apart.
                'blockers' => $reasons,
            ];
        }

        return $this->render('document/workflow.html.twig', [
            'document' => $document,
            'marking' => $document->marking,
            'transitions' => $transitions,
        ]);
    }

    /**
     * Applying is guarded twice over, and deliberately so. The policy below refuses a requester who
     * has no business writing to this document at all; the transition's own guard then decides
     * whether *this* move is allowed. Losing either one would be a hole: without the policy an
     * unauthenticated POST would reach the workflow, and without the guard any writer could publish.
     */
    #[Route('/{transition}', name: 'app_document_transition', methods: ['POST'])]
    #[AccessPolicy('VIEW', subject: new Argument('document'), message: 'You are not allowed to move this document.')]
    public function apply(Document $document, string $transition): Response
    {
        try {
            $this->workflow->apply($document, $transition);
            $this->addFlash('success', \sprintf('Applied "%s" — the document is now %s.', $transition, $document->marking));
        } catch (LogicException $e) {
            // A refused guard leaves as a Workflow exception, not as a 403: the component decided
            // the transition, not the request, and the page is still the requester's to see.
            $this->addFlash('error', \sprintf('"%s" was refused: %s', $transition, $e->getMessage()));
        }

        return $this->redirectToRoute('app_document_workflow', ['id' => $document->id]);
    }
}
