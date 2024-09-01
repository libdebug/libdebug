#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE
from time import perf_counter_ns

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


class LargeBinarySymTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_large_binary_symbol_load_times(self):
        d = debugger(RESOLVE_EXE("node"))

        d.run()

        # Let ignore debuginfod for this test to avoid inconsistencies due to network
        with libcontext.tmp(sym_lvl=4):
            t1_start = perf_counter_ns()

            try:
                # Try resolving a non-existent symbol, which will force the resolution of all symbols.
                d.memory["provola", 2]
                self.assertTrue(False)
            except Exception:
                self.assertTrue(True)

            t1_stop = perf_counter_ns()

        # This must be less than 2 seconds
        self.assertTrue((t1_stop - t1_start) < 2e9)

        d.kill()
        d.terminate()

    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_large_binary_demangle(self):
        d = debugger(RESOLVE_EXE("node"))

        d.run()

        # Let ignore debuginfod for this test to avoid inconsistencies due to network
        with libcontext.tmp(sym_lvl=4):
            # Try resolving a non-existent symbol, which will force the resolution of all symbols.
            try:
                d.memory[
                    "_ZNKSt10_HashtableIN2v88internal8compiler10turboshaft7OpIndexESt4pairIKS4_NS3_16SnapshotTableKeyIbNS3_9NoKeyDataEEEENS1_13ZoneAllocatorISA_EENSt8__detail10_Select1stESt8equal_toIS4_ENS0_4base4hashIS4_EENSD_18_Mod_range_hashingENSD_20_Default_ranged_hashENSD_20_Prime_rehash_policyENSD_17_Hashtable_traitsILb1ELb0ELb1EEEE4findERS6_",
                    2,
                ]
                self.assertTrue(False)
            except Exception:
                self.assertTrue(True)
                pass

            try:
                a = d.memory[
                    "std::_Hashtable<v8::internal::compiler::turboshaft::OpIndex, std::pair<v8::internal::compiler::turboshaft::OpIndex const, v8::internal::compiler::turboshaft::SnapshotTableKey<bool, v8::internal::compiler::turboshaft::NoKeyData> >, v8::internal::ZoneAllocator<std::pair<v8::internal::compiler::turboshaft::OpIndex const, v8::internal::compiler::turboshaft::SnapshotTableKey<bool, v8::internal::compiler::turboshaft::NoKeyData> > >, std::__detail::_Select1st, std::equal_to<v8::internal::compiler::turboshaft::OpIndex>, v8::base::hash<v8::internal::compiler::turboshaft::OpIndex>, std::__detail::_Mod_range_hashing, std::__detail::_Default_ranged_hash, std::__detail::_Prime_rehash_policy, std::__detail::_Hashtable_traits<true, false, true> >::find(v8::internal::compiler::turboshaft::OpIndex const&) const",
                    2,
                ]
                self.assertTrue(True)
            except Exception:
                self.assertTrue(False)
                pass

        d.kill()
        d.terminate()
