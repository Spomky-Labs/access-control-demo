<?php

declare(strict_types=1);

namespace App\Resolver;

use App\Model\Document;
use App\Repository\DocumentStore;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Controller\ValueResolverInterface;
use Symfony\Component\HttpKernel\ControllerMetadata\ArgumentMetadata;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Turns the {id} route parameter into a Document argument, so controllers can
 * type-hint Document directly and #[AccessPolicy] can point its subject at it
 * with new Argument('document').
 */
final readonly class DocumentValueResolver implements ValueResolverInterface
{
    public function __construct(
        private DocumentStore $store,
    ) {
    }

    public function resolve(Request $request, ArgumentMetadata $argument): iterable
    {
        if (Document::class !== $argument->getType()) {
            return [];
        }

        $id = $request->attributes->get('id');
        if (null === $id) {
            return [];
        }

        $document = $this->store->find((int) $id);
        if (null === $document) {
            throw new NotFoundHttpException(\sprintf('Document "%s" does not exist.', $id));
        }

        return [$document];
    }
}
