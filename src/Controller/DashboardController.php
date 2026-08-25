<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The class-level policy guards every action below: the RoleVoter requires the
 * requester to hold ROLE_USER (directly, or through the role hierarchy).
 *
 * An anonymous visitor triggers an AccessDeniedException, which the firewall turns
 * into a redirect to the login page.
 */
#[Route('/dashboard')]
#[AccessPolicy('ROLE_USER')]
final class DashboardController extends AbstractController
{
    #[Route('', name: 'app_dashboard')]
    public function index(): Response
    {
        return $this->render('dashboard/index.html.twig');
    }
}
