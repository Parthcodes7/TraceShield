import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Stars, useTexture } from '@react-three/drei';
import { Globe, MapPin, Server, Shield, Radio } from 'lucide-react';
import * as THREE from 'three';

// Convert Lat/Lng to 3D position on a sphere of given radius
function latLongToVector3(lat, lon, radius) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);

  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);

  return [x, y, z];
}

function EarthGlobe({ lat, lng, hasCoords }) {
  const group = useRef();
  const radius = 2;

  // Load high-res earth textures from Three.js examples repository
  const [colorMap, specularMap] = useTexture([
    'https://raw.githubusercontent.com/mrdoob/three.js/master/examples/textures/planets/earth_atmos_2048.jpg',
    'https://raw.githubusercontent.com/mrdoob/three.js/master/examples/textures/planets/earth_specular_2048.jpg'
  ]);

  useFrame((state, delta) => {
    if (group.current) {
      group.current.rotation.y += delta * 0.1;
    }
  });

  const markerPos = latLongToVector3(lat, lng, radius + 0.02);

  return (
    <group ref={group}>
      {/* Realistic 3D Earth */}
      <mesh>
        <sphereGeometry args={[radius, 64, 64]} />
        <meshStandardMaterial 
          map={colorMap} 
          roughnessMap={specularMap}
          roughness={0.8}
          metalness={0.2}
          emissive="#1a365d"
          emissiveIntensity={0.4}
        />
      </mesh>

      {/* Atmospheric Glow */}
      <mesh>
        <sphereGeometry args={[radius * 1.05, 64, 64]} />
        <meshBasicMaterial color="#44aaff" transparent opacity={0.1} side={THREE.BackSide} />
      </mesh>

      {/* Pulsing Origin Marker */}
      {hasCoords && (
        <mesh position={markerPos}>
          <sphereGeometry args={[0.08, 16, 16]} />
          <meshBasicMaterial color="#ff3344" />
          
          <mesh>
            <sphereGeometry args={[0.15, 16, 16]} />
            <meshBasicMaterial color="#ff3344" transparent opacity={0.4} />
          </mesh>
        </mesh>
      )}
    </group>
  );
}

export default function TraceMap({ geolocation, relayChain }) {
  const hasCoords =
    geolocation &&
    typeof geolocation.latitude === 'number' &&
    typeof geolocation.longitude === 'number';

  const lat = hasCoords ? geolocation.latitude : 20.5937;
  const lng = hasCoords ? geolocation.longitude : 78.9629;

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Globe size={20} style={{ color: 'var(--accent-blue)' }} />
          3D Geographic Attribution & Routing
        </h2>
        {geolocation?.is_known_vpn_or_hosting && (
          <span
            className="status-pill fail"
            title="Origin IP matches commercial datacenter/proxy"
          >
            Cloud / Datacenter ASN
          </span>
        )}
      </div>

      {/* 3D Earth Canvas */}
      <div className="map-container" style={{ position: 'relative', background: '#090d16' }}>
        <Canvas camera={{ position: [0, 0, 6], fov: 45 }}>
          <React.Suspense fallback={null}>
            <ambientLight intensity={2.0} />
            <directionalLight position={[0, 0, 10]} intensity={3.0} />
            <pointLight position={[10, 10, 10]} intensity={2.0} />
            <Stars radius={50} depth={50} count={2000} factor={3} saturation={0} fade speed={0.5} />
            <EarthGlobe lat={lat} lng={lng} hasCoords={hasCoords} />
            <OrbitControls enableZoom={true} enablePan={false} autoRotate={false} minDistance={3} maxDistance={10} />
          </React.Suspense>
        </Canvas>
        
        {/* Origin Status Overlay */}
        <div style={{ position: 'absolute', bottom: '12px', left: '14px', zIndex: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.72rem', letterSpacing: '0.04em' }}>
          GEOLOCATION ATTRIBUTION // ORIGIN MAPPED
        </div>
      </div>

      {/* Origin Metadata Bar */}
      <div className="geo-meta-grid">
        <div className="geo-meta-item">
          <div className="geo-meta-label">Origin Country & City</div>
          <div className="geo-meta-val">
            {geolocation?.origin_country || 'Unknown'}
            {geolocation?.origin_city && geolocation.origin_city !== 'Unknown'
              ? ` • ${geolocation.origin_city}`
              : ''}
          </div>
        </div>

        <div className="geo-meta-item">
          <div className="geo-meta-label">Public Origin IP</div>
          <div className="geo-meta-val" style={{ fontFamily: 'var(--font-mono)' }}>
            {geolocation?.origin_ip || 'N/A'}
          </div>
        </div>

        <div className="geo-meta-item">
          <div className="geo-meta-label">Network / ISP Provider</div>
          <div className="geo-meta-val" title={geolocation?.origin_isp || ''}>
            {geolocation?.origin_isp || 'Unknown'}
          </div>
        </div>
      </div>
    </div>
  );
}
