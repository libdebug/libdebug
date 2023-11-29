from dataclasses import dataclass

@dataclass
class Amd64StackUnwinding():
    """
    Class that provides stack unwinding for the x86_64 architecture.
    """

    def unwind(self, target, target_interface):
        """
        Unwind the stack of a process.
        """

        current_rbp = target.rbp
        stack_trace = [target.rip]

        while current_rbp:
            
            try:
                # Read the return address
                return_address = target_interface._peek_mem(current_rbp + 8)
                
                # Read the previous rbp and set it as the current one
                current_rbp = target_interface._peek_mem(current_rbp)
                
                stack_trace.append(return_address)
            except OSError:
                break

        return stack_trace
