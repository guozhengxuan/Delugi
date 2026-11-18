"""Exercise selection counterfactuals under overlapping rounds and uneven opportunities."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from phase_delta_comparison import inspect_cutoff, observation_phase


def proposal(target, local_candidate, covering, digest):
    return {
        'digest': digest,
        'input': {
            'target_heights': [target, 0, 0, 0],
            'pool': [{'heights': [height, 0, 0, 0]} for height in covering],
            'candidates': [{'producer': 0, 'height': h, 'base_proof': proof}
                           for h, proof in local_candidate],
        },
        'all_reporters': [{'heights': [height, 0, 0, 0]} for height in [*covering, 8]],
    }


class PhaseReduction(unittest.TestCase):
    def test_prefers_first_acceptance_in_time_and_distinguishes_local_proof(self):
        # Round 7 is the first locally accepted proposal including height 5,
        # although round 6 commits first. Rounds 3 and 4 both have local data;
        # round 3 has >=2 covering reports but lacks usable witness proofs.
        proposals = {1:proposal(1, [(6, False)], [1, 1, 1], 'a'),
                     3:proposal(1, [(7, True)], [7, 7, 1], 'b'),
                     4:proposal(1, [(5, True)], [5, 1, 1], 'c'),
                     6:proposal(5, [(5, True)], [5, 6, 6], 'd'),
                     7:proposal(6, [(6, True)], [7, 7, 6], 'e')}
        accepted = [(10,1,'a'), (15,3,'b'), (18,4,'c'), (22,7,'e'), (25,6,'d')]
        actual,r,base_proof,fewer_than_two,counts,support = inspect_cutoff(
            accepted, proposals, 0, 5, 9, 6)
        self.assertEqual((actual,r,base_proof,fewer_than_two),(22,7,15,18))
        self.assertEqual(sum(counts.values()),3)
        self.assertEqual(support['two_covering_with_unselected_fourth'],1)
        self.assertEqual(support['fewer_than_two_even_across_all_four'],1)
        self.assertEqual(support['at_least_two_covering_in_frozen_pool'],1)
        with self.assertRaisesRegex(ValueError,'differs from leader emission'):
            inspect_cutoff([(10,1,'different')],proposals,0,5,9,6)

    def test_phase_residual_is_weighted_by_time_and_clipped_to_the_cohort(self):
        phase=observation_phase([0,2000,10000],[1000,2000,3000,9000])
        self.assertEqual(phase['actual_seal_to_next_own_obs_ms'],2.25)
        # Integral of residual over [1,2] and [2,9] ms on respective intervals.
        self.assertEqual(phase['uniform_time_residual_ms'],(0.5+31.5)/8)
        with self.assertRaisesRegex(ValueError,'does not cover'):
            observation_phase([0,2000,10000],[1000,10001])


if __name__ == '__main__':
    unittest.main()
