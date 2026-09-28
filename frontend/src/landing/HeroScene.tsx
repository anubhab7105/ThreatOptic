import { Component, useEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { easing } from 'maath';
import * as THREE from 'three';
import { useSceneTokens } from './useSceneTokens';

function canUseWebGL(): boolean {
  try {
    const c = document.createElement('canvas');
    return !!(c.getContext('webgl2') || c.getContext('webgl'));
  } catch {
    return false;
  }
}

function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

function hasSaveData(): boolean {
  try {
    const nav = navigator as Navigator & { connection?: { saveData?: boolean } };
    return !!nav.connection?.saveData;
  } catch {
    return false;
  }
}

function isCoarsePointer(): boolean {
  try {
    return window.matchMedia('(hover: none)').matches;
  } catch {
    return false;
  }
}

/* ---------- scene contents (no drei; hand-rolled helpers keep the chunk small) ---------- */

function Envelope({ clay, shade, line }: { clay: string; shade: string; line: string }) {
  const body = useRef<THREE.Mesh>(null);
  const flap = useRef<THREE.Mesh>(null);
  const bodyMat = useMemo(() => new THREE.MeshStandardMaterial({ roughness: 0.85, metalness: 0 }), []);
  const flapMat = useMemo(() => new THREE.MeshStandardMaterial({ roughness: 0.9, metalness: 0 }), []);
  const edgeMat = useMemo(() => new THREE.LineBasicMaterial({ transparent: true, opacity: 0.5 }), []);
  useEffect(() => {
    bodyMat.color.set(clay);
    flapMat.color.set(shade);
    edgeMat.color.set(line);
  }, [clay, shade, line, bodyMat, flapMat, edgeMat]);
  useEffect(
    () => () => {
      bodyMat.dispose();
      flapMat.dispose();
      edgeMat.dispose();
    },
    [bodyMat, flapMat, edgeMat],
  );
  return (
    <group>
      <mesh ref={body} material={bodyMat}>
        <boxGeometry args={[2.1, 1.35, 0.5]} />
      </mesh>
      <mesh ref={flap} material={flapMat} position={[0, 0.52, 0.26]} rotation={[0.5, 0, 0]}>
        <boxGeometry args={[2.0, 0.55, 0.06]} />
      </mesh>
    </group>
  );
}

const NODE_POSITIONS: [number, number, number][] = [
  [2.3, 0.6, -0.4], [-2.1, 0.9, -0.8], [1.6, -1.0, 0.6], [-1.7, -0.7, 0.9],
  [0.7, 1.5, -1.1], [-0.6, 1.6, 0.7], [2.5, -0.4, 0.9], [-2.5, 0.1, 0.4],
  [1.1, 0.3, 1.7], [-1.1, 0.2, -1.7], [0.2, -1.6, -0.9], [-0.3, -1.5, 1.2],
  [1.9, 1.2, 0.8], [-1.9, 1.3, -0.3], [0.1, 0.9, 2.0], [0.4, -0.6, -2.0],
];

function NodeCluster({ accent, line }: { accent: string; line: string }) {
  const group = useRef<THREE.Group>(null);
  const mesh = useRef<THREE.InstancedMesh>(null);
  const mat = useMemo(() => new THREE.MeshStandardMaterial({ roughness: 0.8, metalness: 0 }), []);
  const lineMat = useMemo(() => new THREE.LineBasicMaterial({ transparent: true, opacity: 0.45 }), []);
  const lineGeo = useMemo(() => {
    const pairs: Array<[number, number]> = [[0, 4], [1, 5], [2, 10], [3, 11], [6, 8], [7, 9], [12, 4], [13, 5]];
    const pos = new Float32Array(pairs.length * 6);
    pairs.forEach(([a, b], i) => {
      pos.set([...NODE_POSITIONS[a], ...NODE_POSITIONS[b]], i * 6);
    });
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    return g;
  }, []);
  useEffect(() => {
    mat.color.set(accent);
    lineMat.color.set(line);
  }, [accent, line, mat, lineMat]);
  useEffect(() => {
    const m = mesh.current;
    if (!m) return;
    const dummy = new THREE.Object3D();
    NODE_POSITIONS.forEach((p, i) => {
      dummy.position.set(p[0], p[1], p[2]);
      dummy.updateMatrix();
      m.setMatrixAt(i, dummy.matrix);
    });
    m.instanceMatrix.needsUpdate = true;
  }, []);
  useEffect(
    () => () => {
      mat.dispose();
      lineMat.dispose();
      lineGeo.dispose();
    },
    [mat, lineMat, lineGeo],
  );
  useFrame((state, dt) => {
    if (group.current) group.current.rotation.y += dt * 0.08;
  });
  return (
    <group ref={group}>
      <instancedMesh ref={mesh} args={[undefined, undefined, NODE_POSITIONS.length]} material={mat}>
        <sphereGeometry args={[0.07, 12, 12]} />
      </instancedMesh>
      <lineSegments geometry={lineGeo} material={lineMat} />
    </group>
  );
}

function Rings({ line, accent }: { line: string; accent: string }) {
  const r1 = useRef<THREE.Mesh>(null);
  const r2 = useRef<THREE.Mesh>(null);
  const r3 = useRef<THREE.Mesh>(null);
  const m1 = useMemo(() => new THREE.MeshStandardMaterial({ roughness: 0.85, metalness: 0, transparent: true, opacity: 0.85 }), []);
  const m2 = useMemo(() => new THREE.MeshStandardMaterial({ roughness: 0.85, metalness: 0, transparent: true, opacity: 0.6 }), []);
  const m3 = useMemo(() => new THREE.MeshStandardMaterial({ roughness: 0.85, metalness: 0, transparent: true, opacity: 0.5 }), []);
  useEffect(() => {
    m1.color.set(line);
    m2.color.set(accent);
    m3.color.set(line);
  }, [line, accent, m1, m2, m3]);
  useEffect(
    () => () => {
      m1.dispose();
      m2.dispose();
      m3.dispose();
    },
    [m1, m2, m3],
  );
  useFrame((_, dt) => {
    if (r1.current) r1.current.rotation.z += dt * 0.12;
    if (r2.current) r2.current.rotation.z -= dt * 0.09;
    if (r3.current) r3.current.rotation.z += dt * 0.06;
  });
  return (
    <group rotation={[Math.PI / 2.4, 0.15, 0]}>
      <mesh ref={r1} material={m1}>
        <torusGeometry args={[1.9, 0.022, 10, 90]} />
      </mesh>
      <mesh ref={r2} material={m2}>
        <torusGeometry args={[1.45, 0.018, 10, 80]} />
      </mesh>
      <mesh ref={r3} material={m3}>
        <torusGeometry args={[1.05, 0.014, 8, 72]} />
      </mesh>
    </group>
  );
}

function ScanPlane({ accent }: { accent: string }) {
  const mesh = useRef<THREE.Mesh>(null);
  const mat = useMemo(() => new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.4, depthWrite: false }), []);
  useEffect(() => {
    mat.color.set(accent);
  }, [accent, mat]);
  useEffect(() => () => mat.dispose(), [mat]);
  const matRef = useRef(mat);
  useEffect(() => {
    matRef.current = mat;
  }, [mat]);
  // eslint-disable-next-line react-hooks/immutability -- three.js per-frame material mutation is idiomatic R3F; no React state involved
  useFrame(({ clock }) => {
    const m = mesh.current;
    const mt = matRef.current;
    if (!m || !mt) return;
    const cycle = 7; // seconds per sweep
    const t = (clock.elapsedTime % cycle) / cycle; // 0..1
    // sweep down across the envelope, ease-out
    m.position.y = 0.9 - t * 1.8;
    const edge = Math.min(1, Math.min(t, 1 - t) * 6);
    mt.opacity = 0.12 + 0.3 * edge;
  });
  return (
    <mesh ref={mesh} material={mat}>
      <boxGeometry args={[2.7, 0.03, 1.3]} />
    </mesh>
  );
}

function Rig({ children }: { children: React.ReactNode }) {
  const group = useRef<THREE.Group>(null);
  const target = useRef({ x: 0, y: 0 });
  const allowParallax = useMemo(() => !isCoarsePointer() && !prefersReducedMotion(), []);
  useEffect(() => {
    if (!allowParallax) return;
    const onMove = (e: PointerEvent) => {
      const nx = (e.clientX / window.innerWidth) * 2 - 1;
      const ny = (e.clientY / window.innerHeight) * 2 - 1;
      // max ~6 degrees (0.105 rad)
      target.current.x = THREE.MathUtils.clamp(ny * 0.105, -0.105, 0.105);
      target.current.y = THREE.MathUtils.clamp(nx * 0.105, -0.105, 0.105);
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    return () => window.removeEventListener('pointermove', onMove);
  }, [allowParallax]);
  useFrame(({ clock }, dt) => {
    const g = group.current;
    if (!g) return;
    // idle float: amplitude 0.12, period ~6s
    g.position.y = Math.sin((clock.elapsedTime * Math.PI * 2) / 6) * 0.12;
    if (allowParallax) {
      easing.dampE(g.rotation, [target.current.x, target.current.y, 0], 0.35, dt);
    }
  });
  return <group ref={group}>{children}</group>;
}

function AdaptiveDpr() {
  const setDpr = useThree((s) => s.setDpr);
  const gl = useThree((s) => s.gl);
  const acc = useRef({ frames: 0, time: 0 });
  useEffect(() => {
    try {
      const canvas = gl.domElement;
      const onLost = (e: Event) => e.preventDefault();
      canvas.addEventListener('webglcontextlost', onLost, false);
      return () => canvas.removeEventListener('webglcontextlost', onLost);
    } catch {
      return undefined;
    }
  }, [gl]);
  useFrame((_, dt) => {
    acc.current.frames += 1;
    acc.current.time += dt;
    if (acc.current.frames >= 90) {
      const avg = acc.current.time / acc.current.frames;
      if (avg > 0.026) {
        try {
          setDpr(1);
        } catch {
          /* noop */
        }
      }
      acc.current.frames = 0;
      acc.current.time = 0;
    }
  });
  return null;
}

function HeroCanvas({ onFailed }: { onFailed: () => void }) {
  const tokens = useSceneTokens();
  const [frameloop, setFrameloop] = useState<'always' | 'never'>('always');

  useEffect(() => {
    let idleTimer = 0;
    let offscreen = false;
    const markActive = () => {
      if (!document.hidden && !offscreen) setFrameloop('always');
      window.clearTimeout(idleTimer);
      idleTimer = window.setTimeout(() => setFrameloop('never'), 30000);
    };
    const onVis = () => {
      if (document.hidden) setFrameloop('never');
      else markActive();
    };
    const io =
      'IntersectionObserver' in window
        ? new IntersectionObserver(
            (entries) => {
              offscreen = !entries.some((e) => e.isIntersecting);
              setFrameloop(offscreen || document.hidden ? 'never' : 'always');
            },
            { threshold: 0.05 },
          )
        : null;
    const well = document.getElementById('hero-viewport-well');
    if (well && io) io.observe(well);
    markActive();
    document.addEventListener('visibilitychange', onVis);
    window.addEventListener('pointermove', markActive, { passive: true });
    window.addEventListener('scroll', markActive, { passive: true });
    return () => {
      document.removeEventListener('visibilitychange', onVis);
      window.removeEventListener('pointermove', markActive);
      window.removeEventListener('scroll', markActive);
      window.clearTimeout(idleTimer);
      io?.disconnect();
    };
  }, []);

  return (
    <Canvas
      dpr={[1, 1.5]}
      frameloop={frameloop}
      gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
      camera={{ position: [0, 0.4, 6.4], fov: 38 }}
      onCreated={({ gl }) => {
        const canvas = gl.domElement;
        canvas.addEventListener(
          'webglcontextlost',
          (e) => {
            e.preventDefault();
            onFailed();
          },
          false,
        );
      }}
      onError={onFailed}
    >
      <hemisphereLight args={[tokens.clay, tokens.shade, 0.9]} />
      <directionalLight position={[-4, 5, 4]} intensity={1.1} color={tokens.clay} />
      <directionalLight position={[4, -2, -3]} intensity={0.25} color={tokens.accent} />
      <Rig>
        <Envelope clay={tokens.clay} shade={tokens.shade} line={tokens.line} />
        <Rings line={tokens.line} accent={tokens.accent} />
        <NodeCluster accent={tokens.accent} line={tokens.line} />
        <ScanPlane accent={tokens.accent} />
      </Rig>
      {/* fake contact shadow: flat dark ellipse, no shadow maps */}
      <mesh position={[0, -1.35, -0.4]} rotation={[-Math.PI / 2, 0, 0]}>
        <circleGeometry args={[1.35, 40]} />
        <meshBasicMaterial color={tokens.shade} transparent opacity={0.85} depthWrite={false} />
      </mesh>
      <AdaptiveDpr />
    </Canvas>
  );
}

class HeroBoundary extends Component<{ children: React.ReactNode; fallback: () => void }, { failed: boolean }> {
  constructor(props: { children: React.ReactNode; fallback: () => void }) {
    super(props);
    this.state = { failed: false };
  }
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch() {
    this.props.fallback();
  }
  render() {
    if (this.state.failed) return null;
    return this.props.children;
  }
}

export function HeroScene() {
  const [failed, setFailed] = useState(false);
  const eligible = useMemo(() => {
    try {
      if (prefersReducedMotion() || hasSaveData()) return false;
      if (window.matchMedia('(max-width: 767px)').matches) return false;
      return canUseWebGL();
    } catch {
      return false;
    }
  }, []);
  if (!eligible || failed) return null; // poster tier stays visible underneath
  return (
    <HeroBoundary fallback={() => setFailed(true)}>
      <HeroCanvas onFailed={() => setFailed(true)} />
    </HeroBoundary>
  );
}
