import { Component } from 'react';

/**
 * Isolates a lazy 3D/visual scene: on any render or lazy-import failure it
 * renders nothing, leaving the static poster / SVG fallback underneath in
 * place. A scene failure can never blank the page.
 */
export class SceneBoundary extends Component<{ children: React.ReactNode }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (this.state.failed) return null;
    return this.props.children;
  }
}
