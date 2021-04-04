import angr
import claripy
import sys

def main(argv):
    project = angr.Project('07_angr_symbolic_file')
    start_address = 0x00401462

    filename = 'FYMDJLWG.txt'

    # This is passed to fread() at 0x08048925 as nmemb
    # 0x080488f4      6a40           push 0x40
    symbolic_file_size_bytes = 0x40

    password = claripy.BVS('password', symbolic_file_size_bytes * 8)

    password_file = angr.SimFile(filename,
                                 content=password,
                                 size=symbolic_file_size_bytes)

    initial_state = project.factory.blank_state(
        addr=start_address
    )

    initial_state.fs.insert(filename, password_file)
    initial_state.regs.ebx = 0x404000

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Good Job.' in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Try again.' in stdout_output

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]

        solution = solution_state.solver.eval(password, cast_to=bytes).decode()
        print(solution)
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
