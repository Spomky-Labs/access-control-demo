<?php

declare(strict_types=1);

namespace App\Tests;

use App\Tests\Standalone\StandaloneKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * What a controller can still do in an application that has no Security at all.
 *
 * The two things covered here are the ones a migration trips over first: the helpers on
 * AbstractController, which reach for `security.authorization_checker`, and Security's #[IsGranted]
 * attribute, which its own listener reads. Neither service nor listener exists in this container,
 * and both keep working.
 */
final class StandaloneHelpersTest extends TestCase
{
    private static StandaloneKernel $kernel;

    public static function setUpBeforeClass(): void
    {
        self::$kernel = new StandaloneKernel();
        self::$kernel->boot();
    }

    public static function tearDownAfterClass(): void
    {
        self::$kernel->shutdown();
    }

    public function testTheHelperAnswersThroughTheComponent(): void
    {
        self::assertFalse(self::$kernel->getContainer()->has('security.authorization_checker'), 'nothing of Security here');

        $answers = $this->json('/helper/ask', 'key-editor');

        self::assertTrue($answers['editor']);
        self::assertTrue($answers['reader'], 'the hierarchy applies, as it does everywhere else');
        self::assertFalse($answers['admin']);
    }

    public function testTheHelperAnswersForNobodyToo(): void
    {
        $answers = $this->json('/helper/ask', null);

        self::assertFalse($answers['reader']);
        self::assertFalse($answers['editor']);
        self::assertFalse($answers['admin']);
    }

    /**
     * denyAccessUnlessGranted() throws the component's own AccessDeniedException, which carries
     * #[WithHttpStatus(403)] — and with no firewall to turn a denial into a login redirect, that
     * status is what answers.
     */
    public function testTheGuardHelperRefusesWithA403(): void
    {
        self::assertSame(200, $this->request('/helper/guarded', 'key-admin')->getStatusCode());
        self::assertSame(403, $this->request('/helper/guarded', 'key-editor')->getStatusCode());
        self::assertSame(403, $this->request('/helper/guarded', null)->getStatusCode());
    }

    /**
     * #[IsGranted] is Security's attribute. The bundle registers a listener for it when there is no
     * SecurityBundle, so an application migrating does not have to rewrite every attribute at once.
     */
    public function testSecurityIsGrantedIsHonouredWithoutSecurityBundle(): void
    {
        self::assertSame(200, $this->request('/helper/is-granted', 'key-editor')->getStatusCode());
        self::assertSame(200, $this->request('/helper/is-granted', 'key-admin')->getStatusCode(), 'through the hierarchy');
        self::assertSame(403, $this->request('/helper/is-granted', 'key-reader')->getStatusCode());
    }

    public function testTheListenerReadingItIsTheComponents(): void
    {
        // Both are private services, so the runtime container knows neither by name: the test
        // container is what can be asked.
        $container = self::$kernel->getContainer()->get('test.service_container');

        self::assertTrue($container->has('access_control.listener.is_granted'));
        self::assertFalse($container->has('controller.is_granted_attribute_listener'), 'Security\'s own is not there to read it');
    }

    /**
     * @return array<string, mixed>
     */
    private function json(string $path, ?string $apiKey): array
    {
        $response = $this->request($path, $apiKey);
        self::assertSame(200, $response->getStatusCode());

        return json_decode($response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
    }

    private function request(string $path, ?string $apiKey): Response
    {
        $request = Request::create($path);

        if (null !== $apiKey) {
            $request->headers->set('X-Api-Key', $apiKey);
        }

        return self::$kernel->handle($request);
    }
}
