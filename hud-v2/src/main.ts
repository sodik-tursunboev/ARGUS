import './styles/global.css';
import './styles/compact.css';
import './styles/core.css';
import './styles/snapshot.css';
import './styles/boot.css';
import './styles/polish.css';
import './styles/shell.css';
import './styles/type.css';
import './styles/ux.css';
import './styles/detail.css';
import './styles/cockpit.css';
import './styles/operations.css';
import './styles/core-readability.css';
import './styles/core-lanes.css';
import './styles/core-robot.css';
import './styles/icons.css';
import './styles/stability.css';
import './styles/dashboard.css';
/* Fonts: variable families declared in type.css (single woff2 per family,
   weights 300-700 UI / 100-800 data). The earlier static per-weight
   @fontsource imports were redundant payload next to the variables. */
import { mount } from 'svelte';
import App from './App.svelte';

mount(App, { target: document.getElementById('app')! });
