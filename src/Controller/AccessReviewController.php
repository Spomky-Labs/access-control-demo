<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\DecisionVote;
use App\Repository\DocumentStore;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * A fully programmatic controller: no #[AccessPolicy] attribute anywhere. The guard and
 * the per-document permission matrix are both computed in code, through AccessInspector.
 */
final class AccessReviewController extends AbstractController
{
    #[Route('/permissions', name: 'app_permissions')]
    public function index(AccessInspector $inspector, DocumentStore $store): Response
    {
        // Programmatic guard: ask the service, then decide what to do (here, a login redirect
        // for anonymous visitors via the firewall).
        if (!$inspector->isGranted('ROLE_USER')) {
            throw $this->createAccessDeniedException('Sign in to review your permissions.');
        }

        $rows = [];
        foreach ($store->all() as $document) {
            $view = $inspector->decide('VIEW', $document);
            $edit = $inspector->decide('EDIT', $document);

            $rows[] = [
                'document' => $document,
                'view' => ['granted' => DecisionVote::ACCESS_GRANTED === $view->decision, 'reason' => $view->reason],
                'edit' => ['granted' => DecisionVote::ACCESS_GRANTED === $edit->decision, 'reason' => $edit->reason],
            ];
        }

        return $this->render('access_review/index.html.twig', ['rows' => $rows]);
    }

    /**
     * An admin-facing preview of what *other* accounts may do. The matrix is filled in the
     * template by is_granted_for_user(), which the AccessControl component now answers even with
     * a firewall present: the bundle's SecurityExtensionWithoutAuthorization takes over is_granted()
     * and is_granted_for_user() and leaves Security the rest (impersonation_*, access_decision*).
     *
     * Deciding for another user is native to the component — an AccessRequest names its requester —
     * so no per-user token has to be built. The role hierarchy is applied, which is what makes the
     * manager row hold ROLE_USER and the admin row hold everything.
     */
    #[Route('/permissions/preview', name: 'app_permissions_preview')]
    public function preview(AccessInspector $inspector): Response
    {
        if (!$inspector->isGranted('ROLE_ADMIN')) {
            throw $this->createAccessDeniedException('Only administrators may preview other accounts.');
        }

        $accounts = [
            ['label' => 'user', 'user' => new InMemoryUser('user', null, ['ROLE_USER'])],
            ['label' => 'manager', 'user' => new InMemoryUser('manager', null, ['ROLE_MANAGER'])],
            ['label' => 'admin', 'user' => new InMemoryUser('admin', null, ['ROLE_ADMIN'])],
            ['label' => 'anonymous', 'user' => null],
        ];

        // Role attributes and PUBLIC_ACCESS only: is_granted_for_user() refuses the other
        // authentication states (IS_AUTHENTICATED_*) for someone other than the current requester,
        // and subject voters like DocumentVoter want a real token, which a preview does not have.
        $attributes = ['PUBLIC_ACCESS', 'ROLE_USER', 'ROLE_MANAGER', 'ROLE_ADMIN', 'ROLE_ALLOWED_TO_SWITCH'];

        return $this->render('access_review/preview.html.twig', [
            'accounts' => $accounts,
            'attributes' => $attributes,
            // The one attribute the page explains rather than merely answers, through
            // access_control_decision_for_user(). ROLE_MANAGER is the interesting one: the three
            // accounts reach it three different ways, and the reason says which.
            'explained' => 'ROLE_MANAGER',
        ]);
    }
}
