#version 330

in vec2 t_pos;
uniform sampler2D ourtexture;

out vec4 f_color;

void main() {
  vec2 tsize = textureSize(ourtexture, 0);
  vec2 t_pos_px = t_pos * tsize;
  vec4 color = texture(ourtexture, t_pos);

  // shows the matrix as tiny round pixels
  bool should_show = length(mod(t_pos_px, 1) - 0.5) <= 0.4;

  f_color = float(should_show) * color;
}
