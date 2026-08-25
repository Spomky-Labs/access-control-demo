<?php

declare(strict_types=1);

namespace App\Tests;

use App\Service\Catalogue;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The map of the demo, checked against the application it describes.
 *
 * The links used to live in three templates and drifted: the home page listed pages the playground
 * listed again, with different words, and one of them was describing behaviour that had changed.
 * They are generated from Catalogue now, and these tests are what keeps the generator honest — a
 * page added without a home, or a catalogued page that no longer exists, fails here rather than
 * quietly becoming a dead link.
 */
final class CatalogueTest extends WebTestCase
{
    /**
     * Routes that belong to no section on purpose: the map itself, and the two ends of a session.
     */
    private const array UNSECTIONED = ['app_home', 'app_login', 'app_logout'];

    public function testEverySectionPageIsPublic(): void
    {
        $client = static::createClient();

        foreach (Catalogue::SECTIONS as $id => $section) {
            $client->request('GET', '/'.$id);
            self::assertResponseIsSuccessful(\sprintf('the "%s" section is readable by anyone', $section['label']));
        }
    }

    /**
     * A section page names its own entries and nothing else, so the four do not overlap.
     */
    public function testAPageBelongsToExactlyOneSection(): void
    {
        $seen = [];

        foreach (Catalogue::SECTIONS as $id => $section) {
            foreach ($section['owns'] as $route) {
                self::assertArrayNotHasKey($route, $seen, \sprintf('"%s" is claimed by both "%s" and "%s".', $route, $seen[$route] ?? '', $id));
                $seen[$route] = $id;
            }
        }
    }

    /**
     * Every entry of every section points at a route that exists, with enough parameters to build.
     */
    public function testEveryEntryResolvesToARealPage(): void
    {
        $client = static::createClient();
        $router = static::getContainer()->get(RouterInterface::class);

        foreach (Catalogue::SECTIONS as $id => $section) {
            foreach ($section['entries'] as $entry) {
                self::assertNotNull(
                    $router->getRouteCollection()->get($entry['route']),
                    \sprintf('"%s" in section "%s" names a route that does not exist.', $entry['title'], $id),
                );

                // Also in `owns`, or the navigation would not highlight its own entry.
                self::assertContains($entry['route'], $section['owns'], \sprintf('"%s" is listed by "%s" but not owned by it.', $entry['route'], $id));

                $url = $router->generate($entry['route'], $entry['params'] ?? []);
                $client->request('GET', $url);

                // 403 and the login redirect are legitimate answers here: an entry says what it
                // needs, and an anonymous visitor has none of it. A 404 or a 500 is not.
                self::assertContains(
                    $client->getResponse()->getStatusCode(),
                    [200, 302, 403],
                    \sprintf('%s answered %d.', $url, $client->getResponse()->getStatusCode()),
                );
            }
        }
    }

    /**
     * The point of the map: nothing is reachable and unlisted. A page added without being placed in
     * a section is a page nobody will find.
     */
    public function testNoPageIsOrphaned(): void
    {
        static::createClient();
        $router = static::getContainer()->get(RouterInterface::class);

        $orphans = [];
        foreach ($router->getRouteCollection() as $name => $_route) {
            if (!str_starts_with($name, 'app_') || \in_array($name, self::UNSECTIONED, true)) {
                continue;
            }

            if (null === Catalogue::sectionOf($name)) {
                $orphans[] = $name;
            }
        }

        self::assertSame([], $orphans, 'these routes belong to no section: '.implode(', ', $orphans));
    }

    /**
     * The navigation is generated, so it cannot list a section the catalogue does not have — and
     * cannot miss one either.
     */
    public function testTheMenuIsTheCatalogue(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/');

        $labels = $crawler->filter('header nav a')->each(static fn ($a) => trim($a->text()));

        self::assertSame(
            ['Home', ...array_column(Catalogue::SECTIONS, 'label')],
            $labels,
        );
    }

    /**
     * A page inside a section is given that section's pages, without saying so itself.
     */
    public function testAPageCarriesTheNavigationOfItsSection(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $crawler = $client->request('GET', '/strategies');
        self::assertResponseIsSuccessful();

        $subnav = $crawler->filter('.subnav');
        self::assertCount(1, $subnav);
        self::assertStringContainsString('Decisions', $subnav->text());

        // The entry for the page being read is marked, so the sub-navigation says where you are.
        self::assertSame('Five combining algorithms', trim($crawler->filter('.subnav a.active')->text()));
    }

    public function testTheHomePageListsEverySection(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/');

        $html = $crawler->html();
        foreach (Catalogue::SECTIONS as $section) {
            self::assertStringContainsString($section['label'], $html);

            foreach ($section['entries'] as $entry) {
                self::assertStringContainsString($entry['title'], $html, \sprintf('"%s" is missing from the home page.', $entry['title']));
            }
        }
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
