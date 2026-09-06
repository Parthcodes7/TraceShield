import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import { Globe, MapPin, Server, Shield, Radio } from 'lucide-react';

export default function TraceMap({ geolocation, relayChain }) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);

  const hasCoords =
    geolocation &&
    typeof geolocation.latitude === 'number' &&
    typeof geolocation.longitude === 'number';

  const lat = hasCoords ? geolocation.latitude : 20.5937;
  const lng = hasCoords ? geolocation.longitude : 78.9629;
  const zoom = hasCoords ? 5 : 2;

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Clean up existing map instance if any
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    // Initialize Leaflet map
    const map = L.map(mapContainerRef.current, {
      center: [lat, lng],
      zoom: zoom,
      attributionControl: false,
      zoomControl: true,
    });

    // Dark Matter CartoDB tiles
    L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      {
        maxZoom: 19,
        subdomains: 'abcd',
      }
    ).addTo(map);

    if (hasCoords) {
      // Create animated pulsing radar icon
      const radarIcon = L.divIcon({
        className: 'custom-pulse-marker',
        html: `<div class="pulse-marker"></div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10],
      });

      const marker = L.marker([lat, lng], { icon: radarIcon }).addTo(map);

      // Popup details
      const popupContent = `
        <div style="font-family: var(--font-main, sans-serif); color: #080c14; padding: 4px;">
          <strong style="font-size: 13px; display: block; margin-bottom: 4px;">
            ${geolocation.origin_country || 'Unknown Country'}
            ${geolocation.origin_city && geolocation.origin_city !== 'Unknown' ? `(${geolocation.origin_city})` : ''}
          </strong>
          <div style="font-size: 11px; color: #475569; font-family: monospace;">IP: ${geolocation.origin_ip || 'N/A'}</div>
          <div style="font-size: 11px; color: #475569;">ISP: ${geolocation.origin_isp || 'N/A'}</div>
          ${
            geolocation.is_known_vpn_or_hosting
              ? `<div style="margin-top: 4px; display: inline-block; background: #fee2e2; color: #dc2626; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 10px;">⚠️ Commercial Datacenter / VPN</div>`
              : ''
          }
        </div>
      `;
      marker.bindPopup(popupContent).openPopup();
    }

    mapInstanceRef.current = map;

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [lat, lng, hasCoords, geolocation]);

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Globe size={20} style={{ color: 'var(--accent-cyan)' }} />
          Geographic Attribution & Routing
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

      {/* Leaflet Map Canvas */}
      <div ref={mapContainerRef} className="map-container"></div>

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
