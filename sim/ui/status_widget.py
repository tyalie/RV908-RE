import time
from pathlib import Path
import numpy as np
import moderngl
from pyopengltk import OpenGLFrame

SHADER_DIR = Path(__file__).parent / "shader"


class StatusWidget(OpenGLFrame):
    """
    Simple tkinter Widget that employs OpenGL to quickly retrieve, scale
    and render the video feed and more status information (e.g. squares
    indicating the LED matrix subimages) by the ledset program.

    OpenGL was required as the Linsn LED protocol streams a windows screen capture
    over ethernet as variable sized images (even 512x1024 has been observed) and
    each receiver extracts the subimages for their respective LED matrixes from that
    one video stream.
    """

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)

        self._ctx: None | moderngl.Context = None

    def tkResize(self, evt):
        """overrite resize method not call initgl everytime"""
        self.width, self.height = evt.width, evt.height

        if self._ctx is not None:
            self._ctx.viewport = (0, 0, self.width, self.height)
            self._mat_prog['scale'] = self.calc_scale(self._mat_texture.size)

    def _init_matrix(self, size: tuple[int, int]):
        """Create new texture and numpy array backing it with given dimensions"""
        assert self._ctx is not None

        self.mat_data = np.zeros(shape=(size[0] * size[1], 3), dtype="u1")
        self._mat_texture = self._ctx.texture(size=size, components=3, data=self.mat_data, dtype='f1')

        sampler = self._ctx.sampler(texture=self._mat_texture, filter=(moderngl.NEAREST, moderngl.NEAREST))
        sampler.use()

    def initgl(self):
        """Initalize gl states when the frame is created"""
        self._ctx = moderngl.get_context()
        self._ctx.viewport = (0, 0, self.width, self.height)
        self._ctx.screen.use()

        # setting up transparency
        self._ctx.enable(moderngl.BLEND)
        self._ctx.blend_func = moderngl.SRC_ALPHA, moderngl.ONE_MINUS_SRC_ALPHA

        self._mat_prog = self._ctx.program(
            vertex_shader=(SHADER_DIR / "vertex.vert").read_text(),
            fragment_shader=(SHADER_DIR / "simple_texture.frag").read_text(),
        )

        # our screen filling rectangle (aka two triangles)
        vertices = np.asarray([
            [[-1, -1], [-1, 1], [1, 1]],
            [[-1, -1], [1, -1], [1, 1]]
        ], dtype='f4')

        vbo = self._ctx.buffer(vertices.tobytes())
        self._mat_vao = self._ctx.vertex_array(self._mat_prog, vbo, "in_vert")

        self._init_matrix((1,1))  # we have no size, so let it be 1x1px
        self._mat_prog['scale'] = self.calc_scale(self._mat_texture.size)

    def calc_scale(self, texture_size: None | tuple[int, int]=None):
        """It is important here that one side is always factor 1.
        Otherwise the render will not fill the available space fully"""
        if texture_size is None:
            texture_size = 1, 1
        width, height = self.width / texture_size[0], self.height / texture_size[1]

        if width > height:
            return height / width, 1.0
        else:
            return 1.0, width / height


    def redraw(self):
        """Render a single frame"""
        if self._ctx is None:
            return

        self._ctx.screen.clear(0.2, 0.2, 0.2, 1.0)

        # copy our image to the texture
        self._mat_texture.write(self.mat_data)

        self._mat_vao.render()

    def update_matrix_size(self, width: int, height: int):
        """Update the matrix dimensions"""
        self._init_matrix((width, height))
        self._mat_prog['scale'] = self.calc_scale(self._mat_texture.size)

    def is_ready(self) -> bool:
        return self._ctx is not None
