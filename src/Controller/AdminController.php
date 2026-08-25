<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The whole admin area demands ROLE_ADMIN. A logged-in ROLE_USER gets a 403
 * carrying the custom message below; an anonymous visitor is sent to /login.
 */
#[Route('/admin')]
#[AccessPolicy('ROLE_ADMIN', message: 'Administrators only.')]
final class AdminController extends AbstractController
{
    #[Route('', name: 'app_admin')]
    public function index(): Response
    {
        return $this->render('admin/index.html.twig');
    }

    /**
     * A second, method-level policy stacks on top of the class one: both must pass.
     * The class already guarantees ROLE_ADMIN, so this expression only adds the new
     * requirement — a *fully* authenticated session (not merely remember-me).
     *
     * Note: the ExpressionVoter routes every function of the expression back through
     * the decision manager, so `is_fully_authenticated()` shows up in the profiler as
     * its own IS_AUTHENTICATED_FULLY decision, next to the expression's own entry.
     * Re-checking ROLE_ADMIN here would therefore duplicate the class-level decision.
     */
    #[Route('/reports', name: 'app_admin_reports')]
    #[AccessPolicy(
        new Expression('is_fully_authenticated()'),
        message: 'Fully authenticated administrators only.',
    )]
    public function reports(): Response
    {
        return $this->render('admin/reports.html.twig');
    }
}
