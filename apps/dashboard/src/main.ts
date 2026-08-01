import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-600.css";
import { createPinia } from "pinia";
import { createApp } from "vue";

import App from "./App.vue";
import { router } from "./router";
import "./styles/main.scss";

const app = createApp(App);

app.use(createPinia());
app.use(router);
await router.isReady();
app.mount("#app");
