<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Not a single #[AccessPolicy] attribute here on purpose.
 *
 * Every route below is guarded from the outside by the declarative rules under
 * `access_control.rules` (see config/packages/access_control.yaml). The rule listener
 * runs on kernel.request, just after the firewall has resolved the token, so a forbidden
 * request never reaches these methods: they only run once access has already been granted.
 *
 * The index page itself matches no rule, so it stays public.
 */
#[Route('/zone')]
final class ZoneController extends AbstractController
{
    #[Route('', name: 'app_zone')]
    public function index(): Response
    {
        return $this->render('zone/index.html.twig');
    }

    #[Route('/members', name: 'app_zone_members')]
    public function members(): Response
    {
        return $this->render('zone/area.html.twig', [
            'title' => 'Members area',
            'rule' => "{ path: '^/zone/members', roles: [ROLE_USER] }",
            'lead' => 'Any authenticated account reaches this page — ROLE_USER is granted directly or through the role hierarchy.',
        ]);
    }

    #[Route('/staff', name: 'app_zone_staff')]
    public function staff(): Response
    {
        return $this->render('zone/area.html.twig', [
            'title' => 'Staff area',
            'rule' => "{ path: '^/zone/staff', roles: [ROLE_MANAGER] }",
            'lead' => 'Managers reach this page; admins do too, because ROLE_ADMIN inherits ROLE_MANAGER in the hierarchy.',
        ]);
    }

    #[Route('/admin', name: 'app_zone_admin')]
    public function admin(): Response
    {
        return $this->render('zone/area.html.twig', [
            'title' => 'Admin area',
            'rule' => "{ path: '^/zone/admin', roles: [ROLE_ADMIN] }",
            'lead' => 'Admins only. A plain user or manager is refused before the controller runs.',
        ]);
    }

    #[Route('/local', name: 'app_zone_local')]
    public function local(Request $request): Response
    {
        return $this->render('zone/area.html.twig', [
            'title' => 'Localhost-only area',
            'rule' => "{ path: '^/zone/local', allow_if: \"request.getClientIp() in ['127.0.0.1', '::1']\" }",
            'lead' => \sprintf(
                'No role is involved: the rule grants by network origin. You reached it from %s. From any other address the same rule refuses, whoever you are.',
                $request->getClientIp() ?? 'an unknown address',
            ),
        ]);
    }

    /**
     * The one rule that is not about who is asking. `requires_channel: https` is answered by the
     * component's ChannelListener, which runs ahead of the rule listener — so an insecure request
     * is redirected before anything about it is decided, and the ROLE_USER on the same rule only
     * comes into it once the request returns over HTTPS.
     */
    #[Route('/secure', name: 'app_zone_secure')]
    public function secure(Request $request): Response
    {
        return $this->render('zone/area.html.twig', [
            'title' => 'HTTPS-only area',
            'rule' => "{ path: '^/zone/secure', requires_channel: https, roles: [ROLE_USER] }",
            'lead' => \sprintf(
                'You reached it over %s, and you are signed in. Over plain HTTP the same rule redirects here rather than refusing: a transport is corrected, not denied.',
                $request->getScheme(),
            ),
        ]);
    }

    #[Route('/api', name: 'app_zone_api', methods: ['GET', 'POST'])]
    public function api(Request $request): Response
    {
        // GET matches no rule, so it is open to everyone. Only POST carries the
        // `methods: [POST]` matcher, and there the ROLE_MANAGER policy applies.
        if ($request->isMethod('POST')) {
            return $this->render('zone/area.html.twig', [
                'title' => 'Write accepted',
                'rule' => '{ path: \'^/zone/api\', methods: [POST], roles: [ROLE_MANAGER] }',
                'lead' => 'This POST went through: the matcher selected it and the ROLE_MANAGER policy granted it.',
            ]);
        }

        return $this->render('zone/api.html.twig');
    }
}
