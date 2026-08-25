<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Bundle\AccessControlBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * An application whose URL rules are declared where they have always been — under
 * `security.access_control` — with the component registered on top.
 *
 * The rules are no longer enforced by the firewall: the bridge reads the map SecurityExtension
 * filled, rebuilds them as the component's own AccessRules, and takes `security.access_listener`
 * (and `security.channel_listener`) out of every firewall chain, so one rule is applied once.
 *
 * Nothing in the security.yaml of such an application changes. That is the whole point, and the
 * reason the two keys may not both be filled: they would be the union rather than one of them.
 */
final class SecurityRulesKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param bool $alsoDeclareComponentRules fills `access_control.rules` as well, which is the
     *                                        contradiction the bridge refuses: two filled keys are
     *                                        the union of their rules rather than one of them
     */
    public function __construct(
        private readonly bool $alsoDeclareComponentRules = false,
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new AccessControlBundle();
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('vault', '/vault')->controller([$this, 'reached']);
        $routes->add('members', '/members')->controller([$this, 'reached']);
        $routes->add('open', '/open')->controller([$this, 'reached']);
    }

    public function reached(): Response
    {
        return new Response('reached');
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'act-security-rules',
            'router' => ['utf8' => true],
            'test' => true,
            'http_method_override' => false,
        ]);

        $container->loadFromExtension('security', [
            'password_hashers' => [InMemoryUser::class => 'plaintext'],
            'providers' => ['main' => ['memory' => ['users' => [
                'alice' => ['password' => 'pa$$word', 'roles' => ['ROLE_USER']],
            ]]]],
            'firewalls' => [
                'main' => ['pattern' => '^/', 'http_basic' => null, 'provider' => 'main'],
            ],
            // Declared on Security's key, enforced by the component.
            'access_control' => [
                // ROLE_VAULT is held by nobody: only VaultVoter, which is a voter of the
                // component alone, can grant it. Security's listener would never consult it.
                ['path' => '^/vault', 'roles' => ['ROLE_VAULT']],
                ['path' => '^/members', 'roles' => ['ROLE_USER']],
            ],
        ]);

        // Left empty on purpose: filling `access_control.rules` as well would raise, the two keys
        // being the union of their rules rather than one of them.
        $container->loadFromExtension('access_control', $this->alsoDeclareComponentRules
            ? ['rules' => [['path' => '^/open', 'roles' => ['ROLE_USER']]]]
            : []);

        $container->register(VaultVoter::class, VaultVoter::class)
            ->addTag('access_control.voter');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/act-security-rules/'.($this->alsoDeclareComponentRules ? 'both' : 'cache');
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/act-security-rules/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
