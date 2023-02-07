import datetime
from typing import List

from volatility.framework import interfaces, contexts, objects
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols import intermed

class NamedPipeEnumeration(interfaces.plugins.PluginInterface):
    """Lists the named pipes of a process in a particular windows memory image."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            interfaces.configuration.Requirement(
                name='os',
                description='Windows system',
                query=interfaces.configuration.Query(
                    filter='os == "windows"'
                )
            ),
            interfaces.configuration.Requirement(
                name='pid_list',
                description='Comma separated list of process IDs',
                parameter=interfaces.configuration.Parameter(
                    name="pid_list",
                    required=True,
                    type=str,
                    description='Comma separated list of process IDs'
                ),
            ),
        ]

    def _generator(self):
        pid_list = [int(pid) for pid in self.config["pid_list"].split(",")]

        for task in self.context.list_tasks():
            if task.UniqueProcessId not in pid_list:
                continue

            process = objects.Object("_EPROCESS",
                                     vm=self.context.memory[task.obj_vm],
                                     offset=task.obj_offset)
            process_pipes = []
            for handle in task.ObjectTable.handles():
                if handle.get_object_type() != "File":
                    continue
                file_obj = handle.dereference(self.context)
                if file_obj.file_name_with_device().startswith("\\Device\\NamedPipe\\"):
                    pipe_name = file_obj.file_name_with_device().replace("\\Device\\NamedPipe\\", "")
                    process_pipes.append((pipe_name, file_obj.CreationTime.as_integer()))

            yield (intermed.wstring_to_utf8(process.ImageFileName),
                   process.UniqueProcessId,
                   sorted(process_pipes, key=lambda x: x[1]))

    def run(self):
        data = []
        for process_name, process_id, pipes in self._generator():
            for pipe in pipes:
                data.append([
                    process_name,
                    str(process_id),
                    pipe[0],
                    datetime.datetime.fromtimestamp(pipe[1]).strftime("%Y-%m-%d %H:%M:%S")
                ])
        return TreeGrid([
            ("Process Name", str),
            ("Process ID", int),
            ("Pipe Name", str),
            ("Creation Time", str)
        ], data)
