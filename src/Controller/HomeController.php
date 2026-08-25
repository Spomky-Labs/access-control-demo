<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class HomeController extends AbstractController
{
    /**
     * The landing page. PUBLIC_ACCESS is granted by the AuthenticatedVoter to
     * everyone, authenticated or not, so this page is always reachable.
     */
    #[Route('/', name: 'app_home')]
    #[AccessPolicy('PUBLIC_ACCESS')]
    public function index(): Response
    {
        return $this->render('home/index.html.twig');
    }
}
