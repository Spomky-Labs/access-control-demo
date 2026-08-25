<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use App\Service\Catalogue;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The four section pages, all rendered from the one catalogue.
 *
 * They are public on purpose: a map of what an application guards is not itself a secret, and a
 * visitor should be able to see what there is to try before deciding which account to sign in as.
 * Each entry says what it needs, and the pages themselves do the refusing.
 */
final class GuideController extends AbstractController
{
    #[Route('/guards', name: 'app_guards')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function guards(): Response
    {
        return $this->section('guards');
    }

    #[Route('/decisions', name: 'app_decisions')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function decisions(): Response
    {
        return $this->section('decisions');
    }

    #[Route('/requesters', name: 'app_requesters')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function requesters(): Response
    {
        return $this->section('requesters');
    }

    #[Route('/reasons', name: 'app_reasons')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function reasons(): Response
    {
        return $this->section('reasons');
    }

    private function section(string $id): Response
    {
        return $this->render('guide/section.html.twig', [
            'section' => ['id' => $id, ...Catalogue::SECTIONS[$id]],
        ]);
    }
}
