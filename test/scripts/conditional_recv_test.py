#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import logging
import random

from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE
from libdebug import debugger
from libdebug.utils.search_utils import AhoCorasickMatcher


class ConditionalRecvTest(TestCase):
	def test_aho_corasick(self) -> None:
		with self.subTest(name="matches_first_pattern"):
			matcher = AhoCorasickMatcher([b"ok", b"bye"])
			self.assertEqual(matcher.stateful_search(b"ok"), (0,2))

		with self.subTest(name="matches_second_pattern"):
			matcher = AhoCorasickMatcher([b"bye", b"ok"])
			self.assertEqual(matcher.stateful_search(b"ok"), (1,2))

		with self.subTest(name="streams_across_chunks"):
			matcher = AhoCorasickMatcher([b"aba"])
			self.assertEqual(matcher.stateful_search(b"ab"), (-1,-1))
			self.assertEqual(matcher.stateful_search(b"a"), (0,1))

		with self.subTest(name="overlapping_patterns"):
			matcher = AhoCorasickMatcher([b"aba", b"bab"])
			self.assertEqual(matcher.stateful_search(b"ababa"), (0,3))

		with self.subTest(name="unmatched_prefix_returns_negative"):
			matcher = AhoCorasickMatcher([b"abcd"])
			self.assertEqual(matcher.stateful_search(b"abc"), (-1,-1))
			self.assertEqual(matcher.stateful_search(b"ab"), (-1,-1))

		with self.subTest(name="pattern_with_null_byte"):
			matcher = AhoCorasickMatcher([b"\x00mid\xff"])
			self.assertEqual(matcher.stateful_search(b"\x00mid\xfftail"), (0,5))

		with self.subTest(name="pattern_with_newline_and_tab"):
			matcher = AhoCorasickMatcher([b"\nvalue\t"])
			self.assertEqual(matcher.stateful_search(b"\nvalue\tend"), (0,7))

		with self.subTest(name="pattern_with_high_ascii_markers"):
			matcher = AhoCorasickMatcher([b"\xff\x10\x80OK", b"fallback"])
			self.assertEqual(matcher.stateful_search(b"\xff\x10\x80OKrest"), (0,5))

		with self.subTest(name="single_byte_pattern"):
			matcher = AhoCorasickMatcher([b"\x7f"])
			self.assertEqual(matcher.stateful_search(b"\x7f\x00"), (0,1))

		with self.subTest(name="repeated_partial_chunks_never_match"):
			matcher = AhoCorasickMatcher([b"abcde"])
			self.assertEqual(matcher.stateful_search(b"abcd" * 8), (-1,-1))

		with self.subTest(name="long_pattern_streamed_in_three_chunks"):
			pattern = (b"A\x00B\x01" * 4) + b"\xff"
			matcher = AhoCorasickMatcher([pattern])
			self.assertEqual(matcher.stateful_search(b"A\x00B\x01" * 2), (-1,-1))
			self.assertEqual(matcher.stateful_search(b"A\x00B\x01" * 2), (-1,-1))
			self.assertEqual(matcher.stateful_search(b"\xff"), (0,1))

		with self.subTest(name="first_pattern_preferred_when_overlapping"):
			matcher = AhoCorasickMatcher([b"abcabc", b"bcabc"])
			self.assertEqual(matcher.stateful_search(b"abcabc"), (0,6))

		with self.subTest(name="failure_link_backtracks_within_trie"):
			matcher = AhoCorasickMatcher([b"ababa", b"babab"])
			self.assertEqual(matcher.stateful_search(b"abababa"), (0,5))

		with self.subTest(name="binary_alternating_sequence"):
			matcher = AhoCorasickMatcher([b"\x01\x02\x01\x02\x03"])
			self.assertEqual(matcher.stateful_search(b"\x01\x02\x01\x02\x03\x04"), (0,5))

		with self.subTest(name="pattern_starting_with_zero_byte"):
			matcher = AhoCorasickMatcher([b"\x00start"])
			self.assertEqual(matcher.stateful_search(b"\x00startfinish"), (0,6))

		with self.subTest(name="pattern_with_trailing_zero_byte"):
			matcher = AhoCorasickMatcher([b"trail\x00"])
			self.assertEqual(matcher.stateful_search(b"trail\x00extra"), (0,6))

		with self.subTest(name="multiple_patterns_with_binary_payloads"):
			matcher = AhoCorasickMatcher([b"\x00bad", b"\x00good\xff"])
			self.assertEqual(matcher.stateful_search(b"\x00good\xfftail"), (1,6))

		with self.subTest(name="very_long_binary_pattern"):
			pattern = (b"XYZ\x00" * 16) + b"END"
			matcher = AhoCorasickMatcher([pattern])
			self.assertEqual(matcher.stateful_search((b"XYZ\x00" * 16) + b"END"), (0,67))

		with self.subTest(name="multiple_matches_but_first_reported"):

			with self.assertLogs("libdebug", level="WARNING") as cm:
				matcher = AhoCorasickMatcher([b"match", b"matchmatch"])
				self.assertEqual(matcher.stateful_search(b"matchmatch"), (0,5))

			self.assertTrue(
				any("prefix matching another pattern" in log for log in cm.output),
				f"Expected warning not found in logs. Captured: {cm.output}"
			)

		with self.subTest(name="duplicate_patterns_ignored"):

			with self.assertLogs("libdebug", level="WARNING") as cm:
				matcher = AhoCorasickMatcher([b"dup", b"dup"])
				self.assertEqual(matcher.stateful_search(b"dup"), (0,3))

			self.assertTrue(
				any("is a duplicate" in log for log in cm.output),
				f"Expected duplicate warning not found. Captured: {cm.output}"
			)

		with self.subTest(name="match_after_large_binary_prefix"):
			prefix = b"\x01\x02" * 64
			matcher = AhoCorasickMatcher([prefix + b"\xff"])
			self.assertEqual(matcher.stateful_search(prefix), (-1,-1))
			self.assertEqual(matcher.stateful_search(b"\xff"), (0,1))

	def test_conditional_recv(self) -> None:
		d = debugger(RESOLVE_EXE("conditional_recv_test"))

		for i in range(25):
			pipe = d.run()
			bp = d.breakpoint("break_here", hardware=True, file="binary") # End of main
			d.cont()

			drop = (random.randint(0, 1) == 1)

			patterns = [
				b"Breathe!",
				b"Sunflower.",
				b"Rainbow.",
				b"Three to the right.",
				b"Four to the left.",
				b"450",
				b"This should never happen!"
			]

			index, out = pipe.match_recvuntil(patterns, drop=drop)
			d.wait()

			self.assertTrue(bp.hit_on(d))

			cond_mem_bytes = d.memory["condition", 4, "binary"]
			cond_mem_int = int.from_bytes(cond_mem_bytes, byteorder="little", signed=True)

			self.assertEqual(index + 1, cond_mem_int)
			self.assertNotEqual(index + 1, 7)  # "This should never happen!"

			additional = (patterns[index] if not drop else b"")
			self.assertEqual(out, b"Conditional receive test program\n" + additional)
			d.kill()

		d.terminate()