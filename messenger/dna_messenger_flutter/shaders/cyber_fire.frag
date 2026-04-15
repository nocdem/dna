#version 460 core

#include <flutter/runtime_effect.glsl>

precision mediump float;

uniform vec2  uSize;
uniform float uTime;
uniform float uHeat;
uniform float uRadius;

out vec4 fragColor;

// Inigo Quilez - rounded rect signed distance
// https://iquilezles.org/articles/distfunctions2d/
float sdRoundedBox(vec2 p, vec2 b, float r) {
    vec2 q = abs(p) - b + r;
    return min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - r;
}

vec2 hash2(vec2 p) {
    p = vec2(dot(p, vec2(127.1, 311.7)),
             dot(p, vec2(269.5, 183.3)));
    return -1.0 + 2.0 * fract(sin(p) * 43758.5453123);
}

// Simplex-like 2D noise (fast, cheap, visually sufficient for abstract flames)
float noise2(vec2 p) {
    const float K1 = 0.366025404;
    const float K2 = 0.211324865;

    vec2 i = floor(p + (p.x + p.y) * K1);
    vec2 a = p - i + (i.x + i.y) * K2;
    float m = step(a.y, a.x);
    vec2  o = vec2(m, 1.0 - m);
    vec2  b = a - o + K2;
    vec2  c = a - 1.0 + 2.0 * K2;
    vec3  h = max(0.5 - vec3(dot(a, a), dot(b, b), dot(c, c)), 0.0);
    vec3  n = h * h * h * h * vec3(
        dot(a, hash2(i + vec2(0.0, 0.0))),
        dot(b, hash2(i + o)),
        dot(c, hash2(i + vec2(1.0, 1.0)))
    );
    return dot(n, vec3(70.0));
}

// 2-octave fractional brownian motion
float fbm2(vec2 p) {
    return 0.5 * noise2(p) + 0.25 * noise2(p * 2.0 + vec2(13.0, 7.0));
}

void main() {
    vec2 fragCoord = FlutterFragCoord().xy;
    vec2 p = fragCoord - 0.5 * uSize;
    vec2 halfSize = 0.5 * uSize;

    float borderThickness = 6.0;
    float d = sdRoundedBox(p, halfSize, uRadius);

    // Discard interior and far exterior early - biggest perf win
    if (d < -borderThickness || d > borderThickness) {
        fragColor = vec4(0.0);
        return;
    }

    vec2 uv = fragCoord / uSize;
    float scrollSpeed = 0.3 + uHeat * 1.7;
    vec2 np = vec2(uv.x * 3.0, uv.y * 2.0 - uTime * scrollSpeed);

    float n = fbm2(np);
    float threshold = 0.2 - uHeat * 0.15;
    float flame = smoothstep(threshold, 0.8, n);

    // Color ramp sourced from DnaColors
    vec3 cold = vec3(0.000, 0.831, 1.000);  // #00D4FF DnaColors.primary
    vec3 mid  = vec3(0.000, 0.400, 1.000);  // #0066FF DnaColors.gradientEnd
    vec3 hot  = vec3(0.753, 0.518, 0.812);  // #C084CF DnaColors.accent
    vec3 core = vec3(1.0);

    vec3 color = mix(cold, mid,  flame);
    color = mix(color, hot,  flame * uHeat);
    color = mix(color, core, pow(flame, 4.0) * uHeat);

    float edgeFalloff = smoothstep(borderThickness, 0.0, abs(d));
    float alpha = flame * edgeFalloff;

    fragColor = vec4(color * alpha, alpha);
}
