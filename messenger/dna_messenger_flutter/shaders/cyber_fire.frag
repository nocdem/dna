#version 460 core

#include <flutter/runtime_effect.glsl>

precision mediump float;

uniform vec2  uSize;
uniform float uTime;
uniform float uHeat;
uniform float uRadius;

out vec4 fragColor;

// Inigo Quilez - rounded rect signed distance
float sdRoundedBox(vec2 p, vec2 b, float r) {
    vec2 q = abs(p) - b + r;
    return min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - r;
}

float hash12(vec2 p) {
    vec3 p3 = fract(vec3(p.xyx) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return fract((p3.x + p3.y) * p3.z);
}

// Value noise in [0, 1] — dead simple, guaranteed consistent across GPUs.
float valueNoise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    float a = hash12(i + vec2(0.0, 0.0));
    float b = hash12(i + vec2(1.0, 0.0));
    float c = hash12(i + vec2(0.0, 1.0));
    float d = hash12(i + vec2(1.0, 1.0));
    return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
}

// 3-octave fbm — rich, flickering texture.
float fbm3(vec2 p) {
    float v = 0.0;
    float amp = 0.5;
    for (int i = 0; i < 3; i++) {
        v += amp * valueNoise(p);
        p *= 2.07;
        p += vec2(19.19, 7.13);
        amp *= 0.5;
    }
    return v;
}

void main() {
    vec2 fragCoord = FlutterFragCoord().xy;
    vec2 p = fragCoord - 0.5 * uSize;
    vec2 halfSize = 0.5 * uSize;

    // Wider band so the effect is actually visible inside the card edge.
    float innerBand = 18.0;
    float outerBand = 2.0;
    float d = sdRoundedBox(p, halfSize, uRadius);

    if (d < -innerBand || d > outerBand) {
        fragColor = vec4(0.0);
        return;
    }

    // Normalized position across the band: 0 at innermost, 1 at outer edge.
    float bandT = clamp((d + innerBand) / (innerBand + outerBand), 0.0, 1.0);

    // High-frequency noise so each pixel inside the 18px band has its own
    // flame value. Two noise samples at different speeds give coarse body +
    // fast flicker.
    vec2 uv = fragCoord / uSize.y;  // aspect-correct
    float speed = 0.5 + uHeat * 2.5;

    float body    = fbm3(vec2(uv.x * 10.0, uv.y * 10.0 - uTime * speed));
    float flicker = valueNoise(vec2(uv.x * 35.0, uv.y * 35.0 - uTime * speed * 3.0));
    float n = body * 0.75 + flicker * 0.25;

    // Flame vertical profile: hotter near the edge (bandT ~= 1.0), cooler
    // as we move into the card interior. Multiplied by noise to carve tongues.
    float profile = smoothstep(0.0, 0.6, bandT);
    float flame = smoothstep(0.35 - uHeat * 0.25, 0.95, n) * profile;

    // Cyber plasma ramp — DnaColors: primary → gradientEnd → accent → white.
    vec3 cold = vec3(0.000, 0.831, 1.000);  // #00D4FF
    vec3 mid  = vec3(0.000, 0.400, 1.000);  // #0066FF
    vec3 hot  = vec3(0.753, 0.518, 0.812);  // #C084CF
    vec3 core = vec3(1.0);

    vec3 color = mix(cold, mid, flame);
    color = mix(color, hot,  flame * uHeat);
    color = mix(color, core, pow(flame, 3.0) * uHeat);

    // Outward soft glow + flame body.
    float alpha = flame;
    // Additive emission boost — painter uses BlendMode.plus, so alpha
    // modulates how much is added to the underlying card.
    fragColor = vec4(color * alpha, alpha);
}
