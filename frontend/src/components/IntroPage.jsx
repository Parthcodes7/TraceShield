import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Stars, Text, Float, MeshDistortMaterial, Sparkles } from '@react-three/drei';
import * as THREE from 'three';

// Enhanced central core
function CyberSphere() {
  const coreRef = useRef();
  
  useFrame((state, delta) => {
    if (coreRef.current) {
      coreRef.current.rotation.y += delta * 0.3;
      coreRef.current.rotation.x += delta * 0.2;
    }
  });

  return (
    <group ref={coreRef}>
      {/* Outer Wireframe Energy Shield */}
      <mesh>
        <icosahedronGeometry args={[2, 2]} />
        <meshStandardMaterial 
          color="#00f0ff" 
          wireframe={true} 
          transparent 
          opacity={0.3} 
          emissive="#00f0ff"
          emissiveIntensity={0.5}
        />
      </mesh>

      {/* Pulsing Distorted Inner Core */}
      <mesh>
        <icosahedronGeometry args={[1.6, 64]} />
        <MeshDistortMaterial 
          color="#0a0f1c"
          emissive="#3b82f6"
          emissiveIntensity={0.6}
          roughness={0.1}
          metalness={1}
          distort={0.4}
          speed={3}
        />
      </mesh>

      {/* Deep Solid Core */}
      <mesh>
        <icosahedronGeometry args={[1.2, 2]} />
        <meshStandardMaterial 
          color="#080c14"
          emissive="#6366f1"
          emissiveIntensity={1}
        />
      </mesh>
      
      {/* Energy Sparks around the core */}
      <Sparkles count={150} scale={5} size={2} speed={0.4} color="#00f0ff" opacity={0.8} />
    </group>
  );
}

// 3D Floating Title
function FloatingTitle() {
  return (
    <Float speed={2} rotationIntensity={0.1} floatIntensity={0.5}>
      <group position={[0, 4, 0]}>
        <Text
          fontSize={1.2}
          color="#ffffff"
          anchorX="center"
          anchorY="middle"
          outlineWidth={0.04}
          outlineColor="#00f0ff"
        >
          TraceShield
        </Text>
        <Text
          position={[0, -0.8, 0]}
          fontSize={0.25}
          color="#94a3b8"
          anchorX="center"
          anchorY="middle"
          letterSpacing={0.1}
        >
          FORENSIC CYBER-INTELLIGENCE PLATFORM
        </Text>
      </group>
    </Float>
  );
}

// A Saturn-like ring made of floating feature text
function FeatureRing() {
  const groupRef = useRef();
  
  const features = [
    "Header Forensics",
    "NLP Content Analysis",
    "Geolocation & IP",
    "Threat Fusion Scoring",
    "Adversarial Red-Team",
    "Evidence PDF Dossier"
  ];
  
  const radius = 5; // Radius of the Saturn ring
  
  // Create positions for the text elements in a circle
  const items = useMemo(() => {
    return features.map((feature, i) => {
      const angle = (i / features.length) * Math.PI * 2;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      return { feature, position: [x, 0, z], rotation: [0, -angle + Math.PI / 2, 0] };
    });
  }, [features]);

  // Rotate the entire ring slowly
  useFrame((state, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * 0.15; // Slow rotation
      groupRef.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.5) * 0.1; // Gentle tilt wobble
      groupRef.current.rotation.x = 0.25; // Fixed tilt to look like a Saturn ring
    }
  });

  return (
    <group ref={groupRef}>
      {/* Visual ring lines */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[radius - 0.02, radius + 0.02, 128]} />
        <meshBasicMaterial color="#00f0ff" transparent opacity={0.3} side={THREE.DoubleSide} />
      </mesh>
      <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, -0.1, 0]}>
        <ringGeometry args={[radius - 0.2, radius - 0.18, 128]} />
        <meshBasicMaterial color="#6366f1" transparent opacity={0.15} side={THREE.DoubleSide} />
      </mesh>
      
      {/* Floating Feature Texts */}
      {items.map((item, index) => (
        <Float key={index} speed={2} rotationIntensity={0.1} floatIntensity={0.2}>
          <Text
            position={item.position}
            rotation={item.rotation}
            fontSize={0.3}
            color="#f1f5f9"
            anchorX="center"
            anchorY="middle"
            outlineWidth={0.01}
            outlineColor="#3b82f6"
          >
            {item.feature}
          </Text>
        </Float>
      ))}
    </group>
  );
}

export default function IntroPage({ onEnter }) {
  return (
    <div style={{ position: 'relative', width: '100vw', height: '100vh', backgroundColor: '#04070a', overflow: 'hidden' }}>
      
      {/* 3D Canvas Layer */}
      <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', zIndex: 1 }}>
        <Canvas camera={{ position: [0, 1.5, 12], fov: 45 }}>
          <React.Suspense fallback={null}>
            <ambientLight intensity={0.2} />
            <pointLight position={[10, 10, 10]} intensity={1.5} color="#00f0ff" />
            <pointLight position={[-10, -10, -10]} intensity={1} color="#6366f1" />
            <spotLight position={[0, 10, 0]} intensity={2} color="#ffffff" angle={0.5} penumbra={1} />
            
            <Stars radius={100} depth={50} count={6000} factor={3} saturation={0.5} fade speed={1.5} />
            
            <CyberSphere />
            <FeatureRing />
            <FloatingTitle />
            
            <OrbitControls 
              enableZoom={false} 
              enablePan={false} 
              autoRotate 
              autoRotateSpeed={0.3} 
              maxPolarAngle={Math.PI / 1.8}
              minPolarAngle={Math.PI / 2.5}
            />
          </React.Suspense>
        </Canvas>
      </div>
      
      {/* UI Overlay Layer */}
      <div style={{ 
        position: 'absolute', 
        bottom: '60px', 
        left: '50%', 
        transform: 'translateX(-50%)', 
        zIndex: 10, 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center',
        pointerEvents: 'auto'
      }}>
        <button 
          onClick={onEnter}
          style={{
            background: 'linear-gradient(135deg, #00f0ff 0%, #2563eb 100%)',
            color: '#04070a',
            border: 'none',
            padding: '16px 48px',
            fontSize: '1.05rem',
            fontWeight: 800,
            fontFamily: "'Inter', sans-serif",
            borderRadius: '14px',
            cursor: 'pointer',
            boxShadow: '0 8px 32px rgba(0, 240, 255, 0.4)',
            transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            outline: 'none'
          }}
          onMouseOver={(e) => {
            e.currentTarget.style.transform = 'translateY(-4px) scale(1.05)';
            e.currentTarget.style.boxShadow = '0 16px 40px rgba(0, 240, 255, 0.6)';
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.transform = 'translateY(0) scale(1)';
            e.currentTarget.style.boxShadow = '0 8px 32px rgba(0, 240, 255, 0.4)';
          }}
        >
          Initialize Dashboard
        </button>
      </div>
    </div>
  );
}
