# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.
import angr
import claripy
import sys

def main():
    project = angr.Project("12_angr_veritesting")
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state, veritesting=True)

    def success(state):
        return b"Good Job" in state.posix.dumps(sys.stdout.fileno())

    def failed(state):
        return b"Try again" in state.posix.dumps(sys.stdout.fileno())

    simulation.explore(find=success, avoid=failed)

    if simulation.found:
        solution_state = simulation.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno()))
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()