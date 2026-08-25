<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Every page of the demo, rendered.
 *
 * The other tests each assert something about one page; this one asserts nothing about any of them
 * except that it answers. A demo whose value is its pages needs that: a Twig error in a leaf nobody
 * wrote a test for is exactly what survives an otherwise green suite, and a shared layout means one
 * bad change breaks every page at once.
 *
 * Signed in as the most privileged account, so a refusal here is a deliberate one rather than a
 * missing role.
 */
final class SmokeTest extends WebTestCase
{
    /**
     * Every answer that means the page did its job. A refusal is one of them: several pages exist
     * in order to refuse, and this test is not about who gets in.
     *
     * @var list<int>
     */
    private const array ACCEPTABLE = [
        200, // rendered
        301, // the HTTPS channel of a rule, corrected before anything was decided
        302, // the firewall sending a requester somewhere else
        403, // refused on purpose
    ];

    /**
     * Routes a GET cannot exercise: one ends the session for every later request, the other only
     * answers POST.
     *
     * @var list<string>
     */
    private const array SKIPPED = ['app_logout', 'app_document_transition'];

    public function testEveryPageAnswers(): void
    {
        $client = static::createClient();
        $client->loginUser(new InMemoryUser('admin', 'admin', ['ROLE_ADMIN']));

        $failures = [];

        foreach ($this->urls() as $name => $url) {
            $client->request('GET', $url);
            $status = $client->getResponse()->getStatusCode();

            if (!\in_array($status, self::ACCEPTABLE, true)) {
                $failures[] = \sprintf('%s (%s) answered %d', $name, $url, $status);
            }
        }

        self::assertSame([], $failures, "Pages that did not render:\n".implode("\n", $failures));
    }

    /**
     * A guard against the loop above quietly iterating over nothing.
     */
    public function testThereIsSomethingToSmokeTest(): void
    {
        static::createClient();

        self::assertGreaterThan(30, \count($this->urls()));
    }

    /**
     * @return array<string, string>
     */
    private function urls(): array
    {
        $router = static::getContainer()->get(RouterInterface::class);
        $urls = [];

        foreach ($router->getRouteCollection() as $name => $route) {
            if (!str_starts_with($name, 'app_') || \in_array($name, self::SKIPPED, true)) {
                continue;
            }

            if ([] !== $route->getMethods() && !\in_array('GET', $route->getMethods(), true)) {
                continue;
            }

            // The two placeholders this application uses, filled with values its fixtures have.
            $parameters = [];
            foreach (['id' => 2, 'transition' => 'submit'] as $placeholder => $value) {
                if (str_contains($route->getPath(), '{'.$placeholder.'}')) {
                    $parameters[$placeholder] = $value;
                }
            }

            $urls[$name] = $router->generate($name, $parameters);
        }

        return $urls;
    }
}
