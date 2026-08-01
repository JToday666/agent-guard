// @ts-expect-error — 字体包仅提供构建期副作用入口，不提供类型声明
import "@fontsource-variable/inter";
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
