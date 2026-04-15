#version 460 core

#include <flutter/runtime_effect.glsl>

precision mediump float;

uniform vec2  uSize;
uniform float uTime;
uniform float uHeat;
uniform float uRadius;
uniform float uBoost;  // 0 = normal (cyan cyber), 1 = boosted (warm amber)

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

    // Band width scales with heat so low-like posts have a tight, faint
    // sparkle and high-like posts have a wide, flaring body.
    float innerBand = 6.0 + uHeat * 16.0;   // 6..22 px inward
    float outerBand = 2.0;
    float d = sdRoundedBox(p, halfSize, uRadius);

    if (d < -innerBand || d > outerBand) {
        fragColor = vec4(0.0);
        return;
    }

    float bandT = clamp((d + innerBand) / (innerBand + outerBand), 0.0, 1.0);

    vec2 uv = fragCoord / uSize.y;
    float speed = 0.5 + uHeat * 2.5;

    float body    = fbm3(vec2(uv.x * 10.0, uv.y * 10.0 - uTime * speed));
    float flicker = valueNoise(vec2(uv.x * 35.0, uv.y * 35.0 - uTime * speed * 3.0));
    float n = body * 0.75 + flicker * 0.25;

    // Vertical profile: hotter near the edge, cooler inward.
    float profile = smoothstep(0.0, 0.6, bandT);

    // Aggressive threshold — at low heat very few pixels exceed the cut,
    // at high heat almost all do. This makes flame COVERAGE scale visibly.
    //   heat 0.15 (1 like)  → threshold 0.55, sparse flames
    //   heat 0.45 (7 likes) → threshold 0.38, clearly thicker flames
    //   heat 1.00 (100+)    → threshold 0.15, fully engulfed
    float threshold = 0.60 - uHeat * 0.45;
    float flame = smoothstep(threshold, 0.95, n) * profile;

    // Normal (cold cyber plasma): cyan → blue → lavender
    vec3 coldA = vec3(0.000, 0.831, 1.000);  // #00D4FF DnaColors.primary
    vec3 midA  = vec3(0.000, 0.400, 1.000);  // #0066FF gradientEnd
    vec3 hotA  = vec3(0.753, 0.518, 0.812);  // #C084CF accent

    // Boosted (warm fire): amber → orange → hot pink
    vec3 coldB = vec3(0.961, 0.620, 0.043);  // #F59E0B DnaColors.warning
    vec3 midB  = vec3(0.984, 0.573, 0.235);  // #FB923C orange
    vec3 hotB  = vec3(0.957, 0.447, 0.714);  // #F472B6 hot pink

    vec3 cold = mix(coldA, coldB, uBoost);
    vec3 mid  = mix(midA,  midB,  uBoost);
    vec3 hot  = mix(hotA,  hotB,  uBoost);
    vec3 core = vec3(1.0);  // white-hot shared by both

    vec3 color = mix(cold, mid, flame);
    color = mix(color, hot,  flame * uHeat);
    color = mix(color, core, pow(flame, 3.0) * uHeat);

    // Brightness scales with heat so low-like posts are noticeably dimmer.
    //   heat 0.15 → 0.32x brightness
    //   heat 0.45 → 0.56x
    //   heat 1.00 → 1.0x full
    float intensity = 0.2 + 0.8 * uHeat;
    float alpha = flame * intensity;

    fragColor = vec4(color * alpha, alpha);
}
