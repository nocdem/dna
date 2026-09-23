// Decorative geometry only. The sculpture does not represent live network data.
export function createNetworkArt(canvas) {
  const context = canvas.getContext('2d');
  if (!context) return { setPaused() {} };
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const steps = 180;
  const sides = 24;
  const vertices = [];
  const faces = [];
  let width = 1;
  let height = 1;
  let phase = 0;
  let lastFrame = 0;
  let frame = 0;
  let paused = false;
  let visible = true;
  let pointerX = 0;
  let pointerY = 0;
  let turnX = 0;
  let turnY = 0;

  const center = t => [
    (1.9 + .64 * Math.cos(3 * t)) * Math.cos(2 * t),
    (1.9 + .64 * Math.cos(3 * t)) * Math.sin(2 * t),
    .95 * Math.sin(3 * t),
  ];
  const normalize = v => {
    const length = Math.hypot(...v);
    return v.map(x => x / length);
  };
  const cross = (a, b) => [a[1]*b[2]-a[2]*b[1], a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]];
  for (let i = 0; i < steps; i++) {
    const t = i / steps * Math.PI * 2;
    const position = center(t);
    const next = center(t + .001);
    const tangent = normalize(next.map((v, j) => v - position[j]));
    const normal = normalize(cross(tangent, [0, 0, 1]));
    const binormal = cross(tangent, normal);
    for (let j = 0; j < sides; j++) {
      const angle = j / sides * Math.PI * 2 + t * 2;
      const radial = normal.map((v, k) => v * Math.cos(angle) + binormal[k] * Math.sin(angle));
      vertices.push({ position: position.map((v, k) => v + .43 * radial[k]), normal: radial });
      faces.push([i*sides+j, ((i+1)%steps)*sides+j, ((i+1)%steps)*sides+(j+1)%sides, i*sides+(j+1)%sides]);
    }
  }

  function render() {
    const ax = .54 + turnY;
    const ay = -.31 + turnX + Math.sin(phase * .27) * .18;
    const az = -.27 + phase * .12;
    const cx = Math.cos(ax), sx = Math.sin(ax), cy = Math.cos(ay), sy = Math.sin(ay), cz = Math.cos(az), sz = Math.sin(az);
    function rotate([x, y, z]) {
      const y1 = y*cx-z*sx, z1 = y*sx+z*cx;
      const x2 = x*cy+z1*sy, z2 = -x*sy+z1*cy;
      return [x2*cz-y1*sz, x2*sz+y1*cz, z2];
    }
    const scale = Math.min(width / 6.9, height / 6.5);
    const projected = vertices.map(vertex => {
      const [x, y, z] = rotate(vertex.position);
      const depth = 9 / (9 + z);
      return { x: width*.53+x*scale*depth, y: height*.48+y*scale*depth, z, normal: rotate(vertex.normal) };
    });
    context.clearRect(0, 0, width, height);
    const halo = context.createRadialGradient(width*.54,height*.49,10,width*.54,height*.49,scale*3.2);
    halo.addColorStop(0,'rgba(150,196,85,.15)');
    halo.addColorStop(1,'rgba(126,168,68,0)');
    context.fillStyle = halo;
    context.fillRect(0,0,width,height);

    // A stable sample order and depth sort keep the same pose reproducible.
    const ordered = faces.map((indices,index) => ({ indices,index,depth:indices.reduce((z,i)=>z+projected[i].z,0)/4 }));
    ordered.sort((a,b)=>b.depth-a.depth || a.index-b.index);
    for (const face of ordered) {
      const points = face.indices.map(i => projected[i]);
      const n = points[0].normal;
      const light = Math.max(0, n[0]*-.32+n[1]*-.57+n[2]*-.75);
      const rim = Math.pow(1-Math.abs(n[2]),3)*.15;
      const brightness = .12+light*.78+rim;
      const highlight = Math.pow(Math.max(0, n[0]*-.46+n[1]*-.68+n[2]*-.56), 14);
      context.beginPath();
      context.moveTo(points[0].x,points[0].y);
      for(let i=1;i<4;i++)context.lineTo(points[i].x,points[i].y);
      context.closePath();
      context.fillStyle = `rgb(${Math.min(255, Math.round(156*brightness+highlight*110))},${Math.min(255, Math.round(181*brightness+highlight*100))},${Math.min(255, Math.round(106*brightness+highlight*95))})`;
      context.fill();
      context.strokeStyle = `rgba(${Math.round(151+light*69)},${Math.round(181+light*58)},${Math.round(103+light*51)},${.16+light*.53})`;
      context.lineWidth = .42;
      context.stroke();
    }
    // Small registration marks frame the sculpture without suggesting telemetry.
    context.strokeStyle = '#6a7d4c';
    context.lineWidth = .5;
    [[width*.16,height*.38],[width*.85,height*.66]].forEach(([x,y]) => {
      context.beginPath();context.moveTo(x-4,y);context.lineTo(x+4,y);context.moveTo(x,y-4);context.lineTo(x,y+4);context.stroke();
    });
  }
  function animate(timestamp) {
    frame = 0;
    if (paused || reducedMotion.matches || !visible || document.hidden) return;
    if (timestamp-lastFrame >= 40) {
      const elapsed = lastFrame ? Math.min(timestamp-lastFrame,100) : 40;
      phase += elapsed / 1000;
      turnX += (pointerX-turnX)*.055;
      turnY += (pointerY-turnY)*.055;
      lastFrame = timestamp;
      render();
    }
    frame = requestAnimationFrame(animate);
  }
  function resume() {
    if (!frame && !paused && !reducedMotion.matches && visible && !document.hidden) {
      lastFrame = 0;
      frame = requestAnimationFrame(animate);
    }
  }
  function resize() {
    const bounds = canvas.getBoundingClientRect();
    width = bounds.width;
    height = bounds.height;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio,0,0,ratio,0,0);
    render();
  }
  new ResizeObserver(resize).observe(canvas);
  new IntersectionObserver(entries => { visible=entries[0].isIntersecting; resume(); }).observe(canvas);
  canvas.addEventListener('pointermove', event => {
    const bounds=canvas.getBoundingClientRect();
    pointerX=((event.clientX-bounds.left)/bounds.width-.5)*.3;
    pointerY=((event.clientY-bounds.top)/bounds.height-.5)*.2;
  });
  canvas.addEventListener('pointerleave',()=>{pointerX=0;pointerY=0;});
  document.addEventListener('visibilitychange',resume);
  reducedMotion.addEventListener('change',()=>{render();resume();});
  resize();
  resume();
  return { setPaused(value) { paused=value; if(!paused) resume(); } };
}
