#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase

from libdebug.data.argument_list import ArgumentList


class ArgumentListTest(TestCase):
    def test_callbacks(self):
        arg_list = ArgumentList()

        before_states = []
        after_states = []

        def before_callback(state):
            before_states.append(state.copy())

        def after_callback(state):
            after_states.append(state.copy())

        # Test setting callbacks
        arg_list.set_callbacks(before_callback, after_callback)
        self.assertEqual(arg_list._before_callback, before_callback)
        self.assertEqual(arg_list._after_callback, after_callback)

        # Test callbacks on operations
        arg_list = ArgumentList(["a", "b", "c"])
        arg_list.set_callbacks(
            lambda state: before_states.append(state.copy()),
            lambda state: after_states.append(state.copy())
        )

        # Test append callback
        arg_list.append("d")
        self.assertEqual(before_states[-1], ["a", "b", "c"])
        self.assertEqual(after_states[-1], ["a", "b", "c", "d"])

        # Test remove callback
        arg_list.remove("b")
        self.assertEqual(before_states[-1], ["a", "b", "c", "d"])
        self.assertEqual(after_states[-1], ["a", "c", "d"])

        # Test callbacks receive copies, not references
        received_states = []
        def callback(state):
            received_states.append(state)
            state.append("999")  # Try to modify

        arg_list.set_callbacks(callback, callback)
        arg_list.append("e")

        # Original list should not be affected by callback modifications
        self.assertNotIn("999", arg_list)
        self.assertEqual(len(received_states), 2)  # Before and after callbacks

    def test_prevent_empty(self):
        arg_list = ArgumentList(["1", "2", "3"])

        # Test property getter/setter
        self.assertFalse(arg_list.prevent_empty)
        arg_list.prevent_empty = True
        self.assertTrue(arg_list.prevent_empty)
        arg_list.prevent_empty = False
        self.assertFalse(arg_list.prevent_empty)

        # Test error on empty list
        empty_list = ArgumentList([])
        with self.assertRaises(ValueError) as cm:
            empty_list.prevent_empty = True
        self.assertIn("Cannot enable prevent_empty on an already empty list", str(cm.exception))

        # Test prevent_empty blocks operations that would empty the list
        arg_list = ArgumentList(["only_item"])
        arg_list.prevent_empty = True

        # Should block clear, pop, remove, delete
        with self.assertRaises(ValueError):
            arg_list.clear()
        with self.assertRaises(ValueError):
            arg_list.pop()
        with self.assertRaises(ValueError):
            arg_list.remove("only_item")
        with self.assertRaises(ValueError):
            del arg_list[0]

        # Test partial operations are allowed
        arg_list = ArgumentList(["1", "2", "3"])
        arg_list.prevent_empty = True
        arg_list.pop()  # Should work, still have 2 items
        self.assertEqual(list(arg_list), ["1", "2"])
        arg_list.remove("1")  # Should work, still have 1 item
        self.assertEqual(list(arg_list), ["2"])

        # Now trying to remove last item should fail
        with self.assertRaises(ValueError):
            arg_list.remove("2")

    def test_list_operations(self):
        # Test append
        arg_list = ArgumentList(["1", "2"])
        arg_list.append("3")
        self.assertEqual(list(arg_list), ["1", "2", "3"])

        # Test extend
        arg_list = ArgumentList(["1", "2"])
        arg_list.extend(["3", "4", "5"])
        self.assertEqual(list(arg_list), ["1", "2", "3", "4", "5"])

        # Test insert
        arg_list = ArgumentList(["1", "3"])
        arg_list.insert(1, "2")
        self.assertEqual(list(arg_list), ["1", "2", "3"])

        # Test remove
        arg_list = ArgumentList(["1", "2", "3", "2"])
        arg_list.remove("2")  # Should remove first occurrence
        self.assertEqual(list(arg_list), ["1", "3", "2"])

        # Test pop (default and with index)
        arg_list = ArgumentList(["1", "2", "3"])
        result = arg_list.pop()
        self.assertEqual(result, "3")
        self.assertEqual(list(arg_list), ["1", "2"])
        result = arg_list.pop(0)
        self.assertEqual(result, "1")
        self.assertEqual(list(arg_list), ["2"])

        # Test clear
        arg_list = ArgumentList(["1", "2", "3"])
        arg_list.clear()
        self.assertEqual(list(arg_list), [])

        # Test reverse
        arg_list = ArgumentList(["1", "2", "3"])
        arg_list.reverse()
        self.assertEqual(list(arg_list), ["3", "2", "1"])

        # Test sort
        arg_list = ArgumentList(["3", "1", "2"])
        arg_list.sort()
        self.assertEqual(list(arg_list), ["1", "2", "3"])

        # Test sort with key and reverse
        arg_list = ArgumentList(["apple", "pie", "a"])
        arg_list.sort(key=len)
        self.assertEqual(list(arg_list), ["a", "pie", "apple"])

        arg_list = ArgumentList(["1", "3", "2"])
        arg_list.sort(reverse=True)
        self.assertEqual(list(arg_list), ["3", "2", "1"])

    def test_item_access_and_operators(self):
        # Test __setitem__ with single index
        arg_list = ArgumentList(["1", "2", "3"])
        arg_list[1] = "99"
        self.assertEqual(list(arg_list), ["1", "99", "3"])

        # Test __setitem__ with slice
        arg_list = ArgumentList(["1", "2", "3", "4", "5"])
        arg_list[1:4] = ["20", "30"]
        self.assertEqual(list(arg_list), ["1", "20", "30", "5"])

        # Test __delitem__ with single index
        arg_list = ArgumentList(["1", "2", "3"])
        del arg_list[1]
        self.assertEqual(list(arg_list), ["1", "3"])

        # Test __delitem__ with slice
        arg_list = ArgumentList(["1", "2", "3", "4", "5"])
        del arg_list[1:4]
        self.assertEqual(list(arg_list), ["1", "5"])

        # Test += operator
        arg_list = ArgumentList(["1", "2"])
        arg_list += ["3", "4"]
        self.assertEqual(list(arg_list), ["1", "2", "3", "4"])
        self.assertIsInstance(arg_list, ArgumentList)  # Should return self

        # Test *= operator
        arg_list = ArgumentList(["1", "2"])
        arg_list *= 3
        self.assertEqual(list(arg_list), ["1", "2", "1", "2", "1", "2"])
        self.assertIsInstance(arg_list, ArgumentList)  # Should return self

    def test_callbacks_with_prevent_empty(self):
        arg_list = ArgumentList(["1", "2"])
        arg_list.prevent_empty = True

        before_states = []
        after_states = []

        arg_list.set_callbacks(
            lambda state: before_states.append(state.copy()),
            lambda state: after_states.append(state.copy())
        )

        # This should work (removing one item, leaving one)
        arg_list.remove("1")

        self.assertEqual(len(before_states), 1)
        self.assertEqual(len(after_states), 1)
        self.assertEqual(before_states[0], ["1", "2"])
        self.assertEqual(after_states[0], ["2"])

        # This should fail (trying to remove the last item)
        with self.assertRaises(ValueError):
            arg_list.remove("2")

        # Should have one more before callback but no additional after callback
        self.assertEqual(len(before_states), 2)
        self.assertEqual(len(after_states), 1)  # No after callback because operation failed
        self.assertEqual(before_states[1], ["2"])

    def test_comprehensive_workflow(self):
        arg_list = ArgumentList()

        operation_log = []
        def log_state(state):
            operation_log.append(len(state))

        arg_list.set_callbacks(log_state, log_state)

        # Start with empty list, add items
        arg_list.append("first")
        arg_list.extend(["second", "third"])
        arg_list.insert(1, "middle")
        self.assertEqual(list(arg_list), ["first", "middle", "second", "third"])

        # Enable prevent_empty and do operations
        arg_list.prevent_empty = True
        arg_list.remove("middle")
        arg_list.pop()  # Remove "third"
        self.assertEqual(list(arg_list), ["first", "second"])

        # Sort and reverse
        arg_list.sort()
        arg_list.reverse()
        self.assertEqual(list(arg_list), ["second", "first"])

        # Try to clear (should fail)
        with self.assertRaises(ValueError):
            arg_list.clear()
        self.assertEqual(list(arg_list), ["second", "first"])

        # Check callbacks were called correctly
        expected_calls = 7 * 2 + 1  # 7 successful operations × 2 + 1 failed operation
        self.assertEqual(len(operation_log), expected_calls)
