<?php

declare(strict_types=1);

namespace App\Controller;

use AccessControl\Attribute\AccessPolicy;
use App\Repository\DocumentStore;
use App\Security\Strategy\TwoKeyStrategy;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * One request, decided five different ways.
 *
 * A strategy is not a setting of the application but an argument of the question: the same voters
 * vote the same way, and what changes is how their answers are combined. Naming it per call is what
 * makes that visible — PUBLISH on a locked document is granted or refused depending on nothing but
 * the algorithm asked for.
 *
 * The fifth is the application's own, and it is reached the same way as the four Symfony ships.
 */
final class StrategyController extends AbstractController
{
    /**
     * The name each algorithm answers to, and what it does with the votes.
     *
     * The first four are the component's; the last is App\Security\Strategy\TwoKeyStrategy, which
     * is a strategy purely by implementing the interface — `access_control.strategy` is
     * autoconfigured.
     */
    private const array STRATEGIES = [
        'permit_overrides' => 'affirmative — one grant is enough',
        'deny_overrides' => 'unanimous — a single refusal wins',
        'majority' => 'consensus — the heavier side wins, ties grant',
        'first_applicable' => 'priority — the first voter with an opinion decides',
        'two_keys' => 'the application\'s own — two grants, and no refusal',
    ];

    #[Route('/strategies', name: 'app_strategies')]
    #[AccessPolicy('ROLE_USER', message: 'Sign in to compare the combining algorithms.')]
    public function index(AccessInspector $inspector, DocumentStore $store): Response
    {
        $rows = [];

        foreach ($store->all() as $document) {
            $verdicts = [];

            foreach (array_keys(self::STRATEGIES) as $strategy) {
                // The very same AccessRequest every time. Only the third argument moves.
                $decision = $inspector->decide('PUBLISH', $document, $strategy);

                $verdicts[$strategy] = [
                    'decision' => $decision->decision->value,
                    'granted' => $decision->isGranted(),
                    'reason' => $decision->reason,
                ];
            }

            // The votes themselves, read once, so the table above can be checked by hand. A
            // CastVote pairs an outcome with the voter that reached it, which is what lets the
            // page name who said what rather than only what was said.
            $votes = [];
            foreach ($inspector->decide('PUBLISH', $document)->votes as $vote) {
                $votes[] = [
                    'voter' => (new \ReflectionClass($vote->voter))->getShortName(),
                    'decision' => $vote->outcome->decision->value,
                    'reason' => $vote->outcome->reason,
                ];
            }

            $rows[] = [
                'document' => $document,
                'verdicts' => $verdicts,
                'votes' => $votes,
            ];
        }

        return $this->render('strategy/index.html.twig', [
            'strategies' => self::STRATEGIES,
            'rows' => $rows,
            'custom' => TwoKeyStrategy::class,
        ]);
    }
}
