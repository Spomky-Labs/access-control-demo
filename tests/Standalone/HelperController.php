<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Bundle\Controller\AccessControlTrait;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * A controller in an application that has no Security at all.
 *
 * Two things here would not have worked before the bundle existed:
 *
 *   * isGranted() and denyAccessUnlessGranted(), which AbstractController answers through
 *     `security.authorization_checker` — a service this container does not have. The bundle's
 *     AccessControlTrait falls back to `access_control.checker`, and a trait method wins over the
 *     one inherited from the parent, so nothing else in the controller changes.
 *   * #[IsGranted], which is Security's attribute and was read by Security's listener.
 *     AccessControlBundle registers one of its own when SecurityBundle is absent, so an
 *     application migrating does not have to rewrite every attribute in the same commit.
 *
 * In this repository FrameworkBundle is the 8.2 one, whose AbstractController already answers
 * through AccessControl, which makes the trait redundant here. It is used anyway because that is
 * not true of an application on 8.1 with the component installed beside it — the case the trait
 * exists for.
 */
final class HelperController extends AbstractController
{
    use AccessControlTrait;

    /**
     * The helper as a question rather than as a guard.
     */
    public function ask(): JsonResponse
    {
        return new JsonResponse([
            'reader' => $this->isGranted('ROLE_READER'),
            'editor' => $this->isGranted('ROLE_EDITOR'),
            'admin' => $this->isGranted('ROLE_ADMIN'),
        ]);
    }

    /**
     * The helper as a guard. Without Security the message is the one given and nothing else: an
     * AccessControl denial keeps its diagnostic out of the response on purpose.
     */
    public function guarded(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN', message: 'Administrators only.');

        return new Response('granted');
    }

    /**
     * Security's attribute, read by the component's listener because there is no SecurityBundle
     * here to read it.
     */
    #[IsGranted('ROLE_EDITOR', message: 'Editors only.')]
    public function isGrantedAttribute(): Response
    {
        return new Response('granted');
    }
}
