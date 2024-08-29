import tkinter
from .status_widget import StatusWidget
import multiprocessing as mlp
from multiprocessing import shared_memory
import queue
import os
import numpy as np
from async_tkinter_loop import async_mainloop
import asyncio


class StatusWindowProcess(mlp.Process):
    """
    This class creates, manages and communicates with the status GUI window
    using multiprocessing to seperate the processing from the GUI code.

    It was tried implementing this as threads once, but due to the GIL and the
    glorious use of fast repeating loops in the other part of the project, the
    speeds were not acceptable.
    """

    class _TkWindow(tkinter.Tk):
        """
        Our TK window. By seperating this from the process
        class it is a bit easier to handle the Tk internal states
        and especially it's problems with e.g. multithreading.
        """
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            self.wm_title("Linsn RE 980 Sim")
            self.geometry("400x400")  # TODO
            self.resizable(False, False)

            self.status = StatusWidget(self)
            self.status.pack(fill=tkinter.BOTH, expand=tkinter.YES)
            self.status.animate = 1000 // 30  # ~30fps

    def __init__(self, *args, **kwargs):
        mlp.Process.__init__(self, *args, **kwargs)
        self.daemon = True

        self._queue = mlp.Queue()

        self._shm = None
        self._pid = None

    @staticmethod
    def ipc(func):
        """
        Simple decorator that makes a method into an IPC capable one.
        The arguments and function name are passed as a dict over a queue, so
        they must be pickable.
        """
        def wrapper(self, *args, **kwargs):
            if self._pid == os.getpid():
                return func(self, *args, **kwargs)

            data = dict(
                name=func.__name__,
                args=args,
                kwargs=kwargs
            )
            self._queue.put(data)
        return wrapper

    async def _receive_loop(self):
        """
        Simple async infinite loop that checks the IPC
        queue for new messages and executes the accordingly.
        """

        # need to wait until matrix is ready
        # it is easier to implement it here, then expecting
        # the IPC user to wait
        while not self._window.status.is_ready():
            await asyncio.sleep(0.01)

        while True:
            try:
                item = self._queue.get_nowait()
                self.__getattribute__(item['name'])(*item['args'], **item['kwargs'])
            except queue.Empty:
                # accurs normally when nothing available, so don't bother
                ...
            await asyncio.sleep(0.01)

    def run(self) -> None:
        self._window = self._TkWindow()
        self._pid = os.getpid()

        # store the currrent thread id
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        self._loop.create_task(self._receive_loop())
        # start mainthread
        async_mainloop(self._window)

        del self._window

    def _init_shared_arr(self, width, height, name = None):
        if self._shm is not None:
            del self._mat_data
            self._shm.close()
            self._shm.unlink()

        size = width * height * 3
        if name is None:
            self._shm = shared_memory.SharedMemory(create=True, size=size)
        else:
            self._shm = shared_memory.SharedMemory(name=name)

        self._mat_data = np.ndarray(shape=(width * height, 3), dtype="u1", buffer=self._shm.buf)
        self._mat_data[:] = 0

        return self._shm

    def set_matrix_size(self, width, height):
        """
        For a matrix size refresh, we also need to reinitialize
        the shared memory numpy array. So we don't call the IPC function
        directly, but instead set-up everything before.
        """
        shm = self._init_shared_arr(width, height)
        self.set_matrix_size_ipc(width, height, shm.name)

    @ipc
    def set_matrix_size_ipc(self, width, height, shared_memory_name):
        self._window.status.update_matrix_size(width, height)

        self._init_shared_arr(width, height, shared_memory_name)
        self._window.status.mat_data = self._mat_data

    def receive_data(self, idx: int, data: bytes):
        """
        As _mat_data is a shared memory numpy array that resides in
        both processes, we can just manipulate it in the calling proc.

        This is signifikantly faster, then sending the bytes over an IPC queue.
        """
        self._mat_data.flat[idx:idx + len(data)] = memoryview(data)

    @ipc
    def destroy(self):
        """Closes the window"""
        self._window.destroy()


if __name__ == "__main__":
    w = StatusWindowProcess()
    w.start()

    input("test")
    w.set_matrix_size(512, 256)

    input("hi")

    del w

    input("blub")

