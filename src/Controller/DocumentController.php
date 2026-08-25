<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\Argument;
use App\Model\Document;
use App\Repository\DocumentStore;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The class-level policy keeps the whole section behind ROLE_USER. On top of it,
 * the show/edit actions add a subject-aware policy handled by the DocumentVoter.
 */
#[Route('/documents')]
#[AccessPolicy('ROLE_USER')]
final class DocumentController extends AbstractController
{
    #[Route('', name: 'app_documents')]
    public function index(DocumentStore $store): Response
    {
        return $this->render('document/index.html.twig', [
            'documents' => $store->all(),
        ]);
    }

    /**
     * VIEW is granted to the owner and to any administrator. The subject passed to
     * the voter is the Document resolved from {id} by DocumentValueResolver.
     */
    #[Route('/{id<\d+>}', name: 'app_document_show')]
    #[AccessPolicy('VIEW', subject: new Argument('document'), message: 'You are not allowed to view this document.')]
    public function show(Document $document): Response
    {
        return $this->render('document/show.html.twig', [
            'document' => $document,
        ]);
    }

    /**
     * EDIT is granted to the owner only — an administrator viewing someone else's
     * document is refused here, which the VIEW action would have allowed.
     */
    #[Route('/{id<\d+>}/edit', name: 'app_document_edit')]
    #[AccessPolicy('EDIT', subject: new Argument('document'), message: 'Only the owner can edit this document.')]
    public function edit(Document $document): Response
    {
        return $this->render('document/edit.html.twig', [
            'document' => $document,
        ]);
    }

    /**
     * Two voters answer PUBLISH: DocumentVoter grants it to the owner/admin, while
     * ComplianceVoter vetoes locked documents. This route uses the default
     * "permit_overrides" strategy, so the grant wins even on a locked document.
     */
    #[Route('/{id<\d+>}/publish', name: 'app_document_publish')]
    #[AccessPolicy('PUBLISH', subject: new Argument('document'), strategy: 'permit_overrides', message: 'You may not publish this document.')]
    public function publish(Document $document): Response
    {
        return $this->render('document/publish.html.twig', [
            'document' => $document,
            'strategy' => 'permit_overrides',
        ]);
    }

    /**
     * The very same request, decided with "deny_overrides": now the compliance veto
     * wins and a locked document cannot be published, whoever asks.
     */
    #[Route('/{id<\d+>}/publish-strict', name: 'app_document_publish_strict')]
    #[AccessPolicy('PUBLISH', subject: new Argument('document'), strategy: 'deny_overrides', message: 'Compliance blocks publishing this locked document.')]
    public function publishStrict(Document $document): Response
    {
        return $this->render('document/publish.html.twig', [
            'document' => $document,
            'strategy' => 'deny_overrides',
        ]);
    }

    /**
     * A single, richer rule expressed with ExpressionLanguage and evaluated by the
     * ExpressionVoter. It reads several variables at once — the authentication state,
     * the held roles, the current user and the targeted subject:
     *
     *   fully authenticated AND ( admin OR ( owns the document AND is a manager ) )
     */
    #[Route('/{id<\d+>}/manage', name: 'app_document_manage')]
    #[AccessPolicy(
        new Expression("is_fully_authenticated() and (is_granted('ROLE_ADMIN') or (subject.owner == user.getUserIdentifier() and 'ROLE_MANAGER' in role_names))"),
        subject: new Argument('document'),
        message: 'You are not allowed to manage this document.',
    )]
    public function manage(Document $document): Response
    {
        return $this->render('document/manage.html.twig', [
            'document' => $document,
        ]);
    }
}
