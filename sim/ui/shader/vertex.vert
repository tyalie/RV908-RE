#version 330

// simple vertex shader, that maps to normalized screen coordinates

uniform vec2 scale;

in vec2 in_vert;
out vec2 t_pos;


void main() {
  gl_Position = vec4(in_vert * scale, 0.0, 1.0);

  t_pos = (in_vert + 1) / 2;
  t_pos.y = -t_pos.y;
}
