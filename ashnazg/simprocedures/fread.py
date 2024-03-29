import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


class fread(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fd = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fd)
        #print("simfd", simfd)
        if simfd is None:
            return -1

        ret = simfd.read(dst, size * nm)
        #print("ret val", ret, "size", size*nm)
        return self.state.solver.If(self.state.solver.Or(size == 0, nm == 0), 0, ret // size)


fread_unlocked = fread
