/// <reference types="vite/client" />

// react-simple-maps ships loose types for some sub-props; the installed
// @types/react-simple-maps covers the components we use (ComposableMap,
// Geographies, Geography, Marker). No extra ambient declarations needed here,
// but this file anchors Vite's client types for import.meta.env, ?url imports,
// and the SVG asset in index.html.
