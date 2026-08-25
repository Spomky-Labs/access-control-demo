<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Bundle\AccessControlBundle;
use AccessControl\RequesterBoundChecker;
use AccessControl\Voter\RBAC\RoleHierarchy;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * The demo app the other way round: AccessControl with **no Security at all**.
 *
 * There is no SecurityBundle here, so no firewall, no token, no user provider — and yet the
 * component still decides. Two things make that possible, both recent:
 *
 *   * `access_control.role_hierarchy` — the hierarchy is declarable on the component's own key.
 *     With Security it must stay under `security.role_hierarchy` (the bridge reads it there and
 *     raises if both are declared); this key is for the applications that have no Security.
 *   * the application names its own requester provider, since there is no token storage to alias.
 *
 * Everything else reads the same as in the main app: the same #[AccessPolicy] attribute, the same
 * declarative rules, the same RequesterBoundChecker behind is_granted().
 */
final class StandaloneKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * ROLE_ADMIN reaches ROLE_EDITOR, which reaches ROLE_READER. Declared here on the component's
     * own key — this application has no security.yaml to put it in.
     */
    public const HIERARCHY = [
        'ROLE_ADMIN' => ['ROLE_EDITOR'],
        'ROLE_EDITOR' => ['ROLE_READER'],
    ];

    public function __construct()
    {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new AccessControlBundle();
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('archive', '/archive')->controller([$this, 'archive']);
        $routes->add('publish', '/publish')->controller([$this, 'publish']);
        $routes->add('whoami', '/whoami')->controller([$this, 'whoami']);
        $routes->add('hierarchy', '/hierarchy')->controller([$this, 'hierarchy']);

        // A real controller class, for the two things a kernel method cannot show: the helpers
        // AbstractController offers, and Security's #[IsGranted] read without SecurityBundle.
        $routes->add('helper_ask', '/helper/ask')->controller([HelperController::class, 'ask']);
        $routes->add('helper_guarded', '/helper/guarded')->controller([HelperController::class, 'guarded']);
        $routes->add('helper_is_granted', '/helper/is-granted')->controller([HelperController::class, 'isGrantedAttribute']);
    }

    /**
     * Guarded by a declarative rule (see below), so the method itself carries nothing.
     */
    public function archive(): Response
    {
        return new Response('archive');
    }

    /**
     * Guarded by the very same attribute the main app uses on its controllers.
     */
    #[AccessPolicy('ROLE_EDITOR', message: 'Editors only.')]
    public function publish(): Response
    {
        return new Response('publish');
    }

    /**
     * Asks the questions programmatically, through the checker bound to the current requester —
     * what is_granted() calls behind the scenes, here without a single Security service.
     */
    public function whoami(RequesterBoundChecker $checker): JsonResponse
    {
        return new JsonResponse([
            'reader' => $checker->isGranted('ROLE_READER'),
            'editor' => $checker->isGranted('ROLE_EDITOR'),
            'admin' => $checker->isGranted('ROLE_ADMIN'),
            'public' => $checker->isGranted('PUBLIC_ACCESS'),
        ]);
    }

    /**
     * Walks the hierarchy both ways.
     *
     * Downwards is what every voter asks: holding these roles, which ones are reached?
     * Upwards is the inverse question — which roles reach this one? — answered by
     * getParentRoleNames(). It lives on the RoleHierarchy class rather than on the interface,
     * deliberately: announcing it would oblige every implementation, and the Security adapter
     * cannot honour it. So it is reachable here, where the real implementation is in place, and
     * not in an application that has Security.
     */
    public function hierarchy(Request $request, RoleHierarchy $hierarchy): JsonResponse
    {
        $role = $request->query->getString('role', 'ROLE_ADMIN');

        return new JsonResponse([
            'reaches' => $hierarchy->getReachableRoleNames([$role]),
            'reached_by' => $hierarchy->getParentRoleNames([$role]),
        ]);
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'act-standalone',
            'router' => ['utf8' => true],
            'test' => true,
            'http_method_override' => false,
        ]);

        $container->loadFromExtension('access_control', [
            // The feature this kernel exists for: no Security, so the hierarchy is declared here.
            'role_hierarchy' => self::HIERARCHY,
            'rules' => [
                ['path' => '^/archive', 'roles' => ['ROLE_READER']],
            ],
        ]);

        // No token storage to alias, so the application says who is asking.
        $container->register('test.requester_provider', ApiKeyRequesterProvider::class)
            ->setArguments([new Reference('request_stack')]);
        $container->setAlias('access_control.requester_provider', 'test.requester_provider');

        // Only the interface is aliased for autowiring, and the inverse lookup is not on it.
        // Without Security this service really is a RoleHierarchy, so the class can be asked for.
        $container->setAlias(RoleHierarchy::class, 'access_control.role_hierarchy');

        // The controllers above are methods of the kernel; make them injectable.
        $container->register(self::class, self::class)->setSynthetic(true)->setPublic(true);

        // Autowired as well as autoconfigured: AbstractController::setContainer carries #[Required],
        // and only an autowired definition gets its required methods called. That container is the
        // service locator AccessControlTrait finds `access_control.checker` in.
        $container->register(HelperController::class, HelperController::class)
            ->setAutoconfigured(true)
            ->setAutowired(true)
            ->setPublic(true);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/act-standalone/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/act-standalone/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
