import { memo, useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { SEV_HEX } from '../lib/ui';
import type { Severity } from '../lib/types';

// react-simple-maps needs a topojson/geojson source. We reference the widely
// used world-atlas 110m file from a CDN. ⚠️ RUNTIME VERIFICATION REQUIRED:
// in an air-gapped deployment this URL must be vendored locally under /public
// and swapped here (see web/README notes).
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

export interface ThreatPoint {
  id: string;
  lat: number;
  lng: number;
  severity: Severity;
  label: string;
  count?: number;
}

/**
 * Interactive world threat map. Renders a desaturated slate landmass with
 * severity-colored markers sized by activity. Points are memoized; the map is
 * a pure projection so it re-renders cheaply as live points arrive.
 */
function WorldThreatMapImpl({ points }: { points: ThreatPoint[] }): JSX.Element {
  const markers = useMemo(() => points.slice(0, 500), [points]);

  return (
    <div className="relative h-full w-full">
      <ComposableMap
        projection="geoEqualEarth"
        projectionConfig={{ scale: 155 }}
        width={800}
        height={380}
        style={{ width: '100%', height: '100%' }}
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="#111823"
                stroke="#26323f"
                strokeWidth={0.4}
                style={{
                  default: { outline: 'none' },
                  hover: { fill: '#18212e', outline: 'none' },
                  pressed: { outline: 'none' },
                }}
              />
            ))
          }
        </Geographies>

        {markers.map((m) => {
          const r = Math.min(9, 3 + Math.log2((m.count ?? 1) + 1));
          const hex = SEV_HEX[m.severity];
          return (
            <Marker key={m.id} coordinates={[m.lng, m.lat]}>
              <circle r={r} fill={hex} fillOpacity={0.22} />
              <circle r={r / 2.2} fill={hex}>
                <title>{`${m.label}${m.count ? ` · ${m.count}` : ''}`}</title>
              </circle>
            </Marker>
          );
        })}
      </ComposableMap>

      {markers.length === 0 && (
        <div className="absolute inset-0 grid place-items-center">
          <p className="font-mono text-xs uppercase tracking-widest text-ink-faint">
            No geolocated activity
          </p>
        </div>
      )}
    </div>
  );
}

export const WorldThreatMap = memo(WorldThreatMapImpl);
