<?php

declare(strict_types=1);

namespace App\Twig;

use App\Service\Catalogue;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Puts the catalogue where the layout can read it, so the navigation is generated rather than
 * maintained. A page added to Catalogue::SECTIONS appears in the menu, on the home page and on its
 * section page without a template changing.
 */
final class CatalogueExtension extends AbstractExtension
{
    public function getFunctions(): array
    {
        return [
            new TwigFunction('catalogue_sections', $this->sections(...)),
            new TwigFunction('catalogue_section_of', Catalogue::sectionOf(...)),
        ];
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public function sections(): array
    {
        return Catalogue::SECTIONS;
    }
}
