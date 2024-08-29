#version 330

in vec2 t_pos;
uniform sampler2D ourtexture;

out vec4 f_color;

void main() {
  vec4 color = texture(ourtexture, t_pos);
  f_color = vec4(color[2], color[0], color[1], color[3]);
}
