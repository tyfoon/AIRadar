declare module 'react-globe.gl' {
  import { Component, RefObject } from 'react';

  interface GlobeProps {
    // Container
    width?: number;
    height?: number;
    backgroundColor?: string;
    animateIn?: boolean;

    // Globe appearance
    globeImageUrl?: string;
    bumpImageUrl?: string;
    showGlobe?: boolean;
    showAtmosphere?: boolean;
    showGraticules?: boolean;
    atmosphereColor?: string;
    atmosphereAltitude?: number;

    // Polygons layer
    polygonsData?: any[];
    polygonGeoJsonGeometry?: string | ((d: any) => any);
    polygonCapColor?: string | ((d: any) => string);
    polygonSideColor?: string | ((d: any) => string);
    polygonStrokeColor?: string | ((d: any) => string);
    polygonAltitude?: number | ((d: any) => number);
    polygonCapCurvatureResolution?: number;
    polygonLabel?: string | ((d: any) => string);
    onPolygonClick?: (polygon: any, event: MouseEvent, coords: { lat: number; lng: number }) => void;
    onPolygonHover?: (polygon: any | null, prevPolygon: any | null) => void;
    polygonsTransitionDuration?: number;

    // Points layer
    pointsData?: any[];
    pointLat?: string | ((d: any) => number);
    pointLng?: string | ((d: any) => number);
    pointColor?: string | ((d: any) => string);
    pointAltitude?: number | ((d: any) => number);
    pointRadius?: number | string | ((d: any) => number);
    pointLabel?: string | ((d: any) => string);
    pointsMerge?: boolean;
    pointResolution?: number;
    onPointClick?: (point: any, event: MouseEvent) => void;
    onPointHover?: (point: any | null, prevPoint: any | null) => void;

    // Arcs layer
    arcsData?: any[];
    arcStartLat?: string | ((d: any) => number);
    arcStartLng?: string | ((d: any) => number);
    arcEndLat?: string | ((d: any) => number);
    arcEndLng?: string | ((d: any) => number);
    arcColor?: string | string[] | ((d: any) => string | string[]);
    arcAltitude?: number | string | ((d: any) => number) | null;
    arcAltitudeAutoScale?: number | ((d: any) => number);
    arcStroke?: number | string | ((d: any) => number) | null;
    arcCurveResolution?: number;
    arcCircularResolution?: number;
    arcDashLength?: number | ((d: any) => number);
    arcDashGap?: number | ((d: any) => number);
    arcDashAnimateTime?: number | ((d: any) => number);
    arcLabel?: string | ((d: any) => string);
    onArcClick?: (arc: any, event: MouseEvent) => void;
    onArcHover?: (arc: any | null, prevArc: any | null) => void;
    arcsTransitionDuration?: number;

    // Interaction
    enablePointerInteraction?: boolean;
    onGlobeClick?: (coords: { lat: number; lng: number }, event: MouseEvent) => void;

    // Camera
    pointOfView?: { lat?: number; lng?: number; altitude?: number };
  }

  interface GlobeInstance {
    controls(): {
      autoRotate: boolean;
      autoRotateSpeed: number;
      enableZoom: boolean;
      minDistance: number;
      maxDistance: number;
    };
    pointOfView(pov: { lat?: number; lng?: number; altitude?: number }, transitionMs?: number): void;
    scene(): any;
    camera(): any;
    renderer(): any;
  }

  const Globe: React.ForwardRefExoticComponent<GlobeProps & React.RefAttributes<GlobeInstance>>;
  export default Globe;
}
